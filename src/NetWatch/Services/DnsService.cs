using System.Collections.Concurrent;
using System.Net;
using NetWatch.Models;

namespace NetWatch.Services;

public sealed record DnsStreamItem(DateTime TimeUtc, int Pid, string Domain, string Ips, bool Alert, string AlertText);

/// DNS 数据消化与劫持启发式：
///  - IP→域名 被动反向映射（供连接表/目的地显示域名，不做任何对外查询）
///  - 公网域名 → 内网/回环 IP（高危）
///  - 进程使用非系统配置的 DNS 服务器（中危）
///  - 同域名解析结果剧烈波动（低危提示）
public sealed class DnsService
{
    private readonly ConcurrentQueue<DnsStreamItem> _stream = new();
    private readonly ConcurrentQueue<(DateTime Time, RiskLevel Level, string Text)> _alerts = new();

    private readonly ConcurrentDictionary<string, (string Domain, DateTime Utc)> _ip2dom = new();
    private readonly ConcurrentDictionary<int, ConcurrentQueue<(string Domain, DateTime Utc)>> _pidDomains = new();
    private readonly ConcurrentDictionary<string, List<(DateTime Utc, string Ip)>> _domHistory = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, DateTime> _lastFlag = new(StringComparer.OrdinalIgnoreCase);

    private volatile HashSet<string> _resolvers = new(StringComparer.OrdinalIgnoreCase);

    public int AlertCount { get; private set; }

    /// 由 NetConfigService 每次轮询后注入当前系统 DNS 服务器
    public void SetResolvers(IEnumerable<string> servers)
        => _resolvers = new HashSet<string>(servers, StringComparer.OrdinalIgnoreCase);

    /// 内核 UDP:53 事件检查（ETW 线程调用）
    public void InspectNetEvent(NetEvent e)
    {
        if (!e.IsSend || e.Proto != NetProto.Udp || e.RemotePort != 53) return;
        if (e.RemoteIp == null || e.IsLoopback) return;
        if (_resolvers.Contains(e.RemoteIp)) return;

        var key = $"dns:{e.Pid}:{e.RemoteIp}";
        if (_lastFlag.TryGetValue(key, out var t) && (DateTime.UtcNow - t).TotalMinutes < 10) return;
        _lastFlag[key] = DateTime.UtcNow;

        _alerts.Enqueue((e.TimeUtc, RiskLevel.Medium,
            $"进程 PID {e.Pid} 正在向非系统 DNS 服务器 {e.RemoteIp}:53 发起查询——恶意软件常用此法绕过系统 DNS 配置（正常软件内置解析器也会触发，可结合进程判断）"));
    }

    /// DNS-Client 解析结果（ETW 线程调用）
    public void OnDns(DnsEvent d)
    {
        // 进程最近查询的域名
        var q = _pidDomains.GetOrAdd(d.Pid, _ => new ConcurrentQueue<(string, DateTime)>());
        q.Enqueue((d.Domain, d.TimeUtc));
        while (q.Count > 30) q.TryDequeue(out _);

        // IP → 域名 被动映射
        foreach (var ip in d.Ips)
            if (IPAddress.TryParse(ip, out _))
                _ip2dom[ip] = (d.Domain, d.TimeUtc);
        PruneMap();

        // UI 实时流
        _stream.Enqueue(new DnsStreamItem(d.TimeUtc, d.Pid, d.Domain, string.Join(", ", d.Ips), false, ""));

        if (!Util.IsPublicDomain(d.Domain))
        {
            Flag(d, RiskLevel.Low,
                $"域名 {d.Domain} 解析到内网/回环地址（本地域名，通常正常）", "loc:", quiet: true);
            return;
        }

        // 劫持启发式：公网域名 → 私有地址
        foreach (var ip in d.Ips)
        {
            if (ip == "0.0.0.0")
            {
                Flag(d, RiskLevel.Medium, $"公网域名 {d.Domain} 被解析到 0.0.0.0——常见于广告屏蔽工具，也可能是劫持屏蔽");
                break;
            }
            if (IpIs(ip, Util.IsLanIp) || IpIs(ip, Util.IsLoopbackIp))
            {
                Flag(d, RiskLevel.High, $"公网域名 {d.Domain} 被解析到内网/回环地址 {ip}——典型 DNS 劫持症状（本地开发环境/AdGuard 类工具可忽略）");
                break;
            }
        }

        // 解析波动
        if (_domHistory.TryGetValue(d.Domain, out var hist))
        {
            List<(DateTime Utc, string Ip)> snap;
            lock (hist) snap = hist.Where(x => (d.TimeUtc - x.Utc).TotalSeconds <= 60).ToList();
            var distinct = snap.Select(x => x.Ip).Distinct().Count();
            if (distinct >= 6)
                Flag(d, RiskLevel.Low, $"域名 {d.Domain} 60 秒内解析出 {distinct} 个不同地址——可能是 CDN 调度，也可能是解析被污染", "vol:");
        }
    }

    private void Flag(DnsEvent d, RiskLevel lv, string text, string keyPrefix = "hij:", bool quiet = false)
    {
        var key = keyPrefix + d.Domain.ToLowerInvariant();
        if (!quiet)
        {
            if (_lastFlag.TryGetValue(key, out var t) && (DateTime.UtcNow - t).TotalMinutes < 10) return;
            _lastFlag[key] = DateTime.UtcNow;
            AlertCount++;
        }
        _alerts.Enqueue((d.TimeUtc, lv, text));
        _stream.Enqueue(new DnsStreamItem(d.TimeUtc, d.Pid, d.Domain, string.Join(", ", d.Ips), !quiet, text));
    }

    private static bool IpIs(string ip, Func<IPAddress, bool> f) =>
        IPAddress.TryParse(ip, out var a) && f(a);

    public string? LookupDomain(string ip) =>
        _ip2dom.TryGetValue(ip, out var v) ? v.Domain : null;

    public List<string> RecentDomains(int pid, int max = 12)
    {
        if (!_pidDomains.TryGetValue(pid, out var q)) return new List<string>();
        return q.Where(x => (DateTime.UtcNow - x.Utc).TotalMinutes < 15)
                .Select(x => x.Domain)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(max)
                .ToList();
    }

    public List<DnsStreamItem> DrainStream()
    {
        var list = new List<DnsStreamItem>();
        while (_stream.TryDequeue(out var it)) list.Add(it);
        return list;
    }

    public List<(DateTime Time, RiskLevel Level, string Text)> DrainAlerts()
    {
        var list = new List<(DateTime, RiskLevel, string)>();
        while (_alerts.TryDequeue(out var a)) list.Add(a);
        return list;
    }

    private void PruneMap()
    {
        if (_ip2dom.Count <= 4096) return;
        var cutoff = DateTime.UtcNow - TimeSpan.FromMinutes(10);
        foreach (var kv in _ip2dom)
            if (kv.Value.Utc < cutoff)
                _ip2dom.TryRemove(kv.Key, out _);
    }
}
