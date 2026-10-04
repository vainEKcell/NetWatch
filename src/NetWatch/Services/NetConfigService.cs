using System.Collections.Concurrent;
using System.IO;
using System.Net.NetworkInformation;
using System.Text;
using Microsoft.Win32;
using NetWatch.Models;
using NetWatch.Native;

namespace NetWatch.Services;

public sealed record AdapterInfo(string Name, string Status, string[] Ips, string[] Gateways, string[] Dns);
public sealed record HostEntry(string Ip, string[] Hosts);
public sealed record NetConfigSnapshot(
    AdapterInfo[] Adapters,
    string ProxyText,
    string WinHttpText,
    IReadOnlyList<HostEntry> Hosts,
    DateTime HostsModified,
    string[] AllDns);

/// 配置层 DNS 劫持监控：DNS 服务器 / 系统代理 / WinHTTP 代理 / hosts 文件的变更检测（零流量）
public sealed class NetConfigService : IDisposable
{
    public static readonly string HostsPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.System),
        "drivers", "etc", "hosts");

    private readonly Timer _timer;
    private NetConfigSnapshot? _last;
    private string _lastHostsHash = "";

    /// UI 消费：配置变更事件
    public ConcurrentQueue<ConfigChange> Changes { get; } = new();
    /// 当前快照（UI 每 tick 读取）
    public volatile NetConfigSnapshot Snapshot = EmptySnapshot();

    public NetConfigService()
    {
        _timer = new Timer(_ => SafePoll(), null, 500, 10_000);
    }

    private void SafePoll()
    {
        try { Poll(); } catch (Exception ex) { Log.Error("网络配置轮询失败", ex); }
    }

    private void Poll()
    {
        var adapters = new List<AdapterInfo>();
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces()
                     .Where(n => n.NetworkInterfaceType != NetworkInterfaceType.Loopback))
        {
            try
            {
                var ipProps = nic.GetIPProperties();
                adapters.Add(new AdapterInfo(
                    nic.Name,
                    nic.OperationalStatus == OperationalStatus.Up ? "已连接" : "断开",
                    ipProps.UnicastAddresses.Select(a => a.Address.ToString()).ToArray(),
                    ipProps.GatewayAddresses.Select(g => g.Address.ToString()).ToArray(),
                    ipProps.DnsAddresses.Select(d => d.ToString()).ToArray()));
            }
            catch { }
        }

        var allDns = adapters.Where(a => a.Status == "已连接")
                             .SelectMany(a => a.Dns)
                             .Distinct(StringComparer.OrdinalIgnoreCase)
                             .ToArray();

        var (proxyText, _) = ReadWinInetProxy();
        var winHttp = NativeMethods.GetWinHttpProxy();
        var hosts = ReadHosts(out var hostsModified);
        var hostsHash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
            Encoding.UTF8.GetBytes(string.Join("|", hosts.Select(h => h.Ip + ":" + string.Join(",", h.Hosts))))));

        var snap = new NetConfigSnapshot(adapters.ToArray(), proxyText, winHttp, hosts, hostsModified, allDns);
        var old = Interlocked.Exchange(ref Snapshot, snap);
        _last = snap;

        if (old == null) return; // 首轮为基线，不产生“变更”

        if (!old.AllDns.SequenceEqual(allDns) && !new HashSet<string>(old.AllDns, StringComparer.OrdinalIgnoreCase).SetEquals(allDns))
            Changes.Enqueue(new ConfigChange(DateTime.UtcNow, "DNS 服务器",
                Fmt(old.AllDns), Fmt(allDns), true));

        if (old.ProxyText != proxyText)
            Changes.Enqueue(new ConfigChange(DateTime.UtcNow, "系统代理 (WinINET)",
                old.ProxyText, proxyText, true));

        if (old.WinHttpText != winHttp)
            Changes.Enqueue(new ConfigChange(DateTime.UtcNow, "WinHTTP 代理",
                old.WinHttpText, winHttp, false));

        if (hostsHash != _lastHostsHash)
        {
            if (_lastHostsHash.Length > 0)
                Changes.Enqueue(new ConfigChange(DateTime.UtcNow, "hosts 文件",
                    $"{old.Hosts.Count} 条生效映射", $"{hosts.Count} 条生效映射", true));
            _lastHostsHash = hostsHash;
        }

        static string Fmt(string[] xs) => xs.Length == 0 ? "（无）" : string.Join(", ", xs);
    }

    private (string Text, string? AutoConfig) ReadWinInetProxy()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings");
            if (key == null) return ("未启用", null);
            int enable = key.GetValue("ProxyEnable") is int v ? v : 0;
            string? server = key.GetValue("ProxyServer") as string;
            string? pac = key.GetValue("AutoConfigURL") as string;
            string text = enable == 1 && !string.IsNullOrEmpty(server) ? $"已启用: {server}" : "未启用";
            if (!string.IsNullOrEmpty(pac)) text += $"　(PAC 脚本: {pac})";
            return (text, pac);
        }
        catch { return ("读取失败", null); }
    }

    private List<HostEntry> ReadHosts(out DateTime modified)
    {
        modified = default;
        try
        {
            if (!File.Exists(HostsPath)) return new List<HostEntry>();
            modified = File.GetLastWriteTime(HostsPath);
            var map = new List<HostEntry>();
            foreach (var raw in File.ReadAllLines(HostsPath))
            {
                var line = raw.Trim();
                if (line.Length == 0 || line.StartsWith('#')) continue;
                int comment = line.IndexOf('#');
                if (comment >= 0) line = line[..comment].Trim();
                var parts = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 2) continue;
                map.Add(new HostEntry(parts[0], parts[1..]));
            }
            return map;
        }
        catch { return new List<HostEntry>(); }
    }

    private static NetConfigSnapshot EmptySnapshot() =>
        new(Array.Empty<AdapterInfo>(), "读取中…", "读取中…", Array.Empty<HostEntry>(), default, Array.Empty<string>());

    public void Dispose() => _timer.Dispose();
}
