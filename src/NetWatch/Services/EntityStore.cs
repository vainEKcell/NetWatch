using System.Collections.Concurrent;
using System.IO;
using NetWatch.Models;
using NetWatch.Native;

namespace NetWatch.Services;

/// 实体仓库：进程实例、软件身份、目的地、服务四类实体 + 相互关系。
/// 事实层——只登记“存在什么、何时出现”，不做任何善恶判断。
public sealed class EntityStore
{
    private readonly ConcurrentDictionary<int, ProcessInstance> _processes = new();
    private readonly ConcurrentDictionary<string, SoftwareIdentity> _identities = new();
    private readonly ConcurrentDictionary<string, DestinationEntity> _destinations = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, ServiceEntity> _services = new(StringComparer.OrdinalIgnoreCase);

    // PID → 身份键的派生缓存（签名/路径变化才重算）
    private readonly ConcurrentDictionary<int, (string Sig, string Path, string Key)> _identityCache = new();
    private volatile Dictionary<int, List<ServiceEntity>> _servicesByPid = new();

    public IReadOnlyDictionary<int, ProcessInstance> Processes => _processes;
    public IReadOnlyDictionary<string, SoftwareIdentity> Identities => _identities;
    public IReadOnlyDictionary<string, DestinationEntity> Destinations => _destinations;
    public IReadOnlyDictionary<string, ServiceEntity> Services => _services;

    public ProcessInstance? GetProcess(int pid) =>
        _processes.TryGetValue(pid, out var p) ? p : null;

    public SoftwareIdentity? GetIdentity(string? key) =>
        key != null && _identities.TryGetValue(key, out var i) ? i : null;

    public List<ServiceEntity> ServicesOf(int pid) =>
        _servicesByPid.TryGetValue(pid, out var list) ? list : new List<ServiceEntity>();

    // ---------- 进程实例 ----------

    /// 由 ProcessTracker 的解析结果登记/刷新进程实例，并派生软件身份。
    /// 受保护进程读不到 MainModule 路径时，退回内核 rundown 命令行中的路径（如杀软 avp.exe）。
    public void ApplyProcessEntry(ProcessEntry e)
    {
        var inst = _processes.GetOrAdd(e.Pid, _ => new ProcessInstance { Pid = e.Pid });
        inst.Name = e.Name;
        inst.Path = e.Path;
        inst.StartTimeUtc ??= e.StartTimeUtc;
        if (e.Exited) inst.ExitTimeUtc ??= DateTime.UtcNow;

        var effectivePath = e.Path ?? ExtractExePath(inst.CommandLine);

        // 命令行回退路径可补一次签名校验（结果按路径缓存在 Authenticode 内）
        if (e.Signature == SignatureState.Unknown && !string.IsNullOrEmpty(effectivePath) && File.Exists(effectivePath))
        {
            var (st, subj) = Authenticode.Verify(effectivePath);
            if (st != SignatureState.Unknown) { e.Signature = st; e.SignatureSubject ??= subj; }
        }

        var key = IdentityKeyFor(e.Pid, effectivePath, e.Signature, e.SignatureSubject, e.ProductName, e.Name);
        inst.IdentityKey = key;
        var id = _identities.GetOrAdd(key, _ => new SoftwareIdentity { Key = key });
        id.LastSeenUtc = DateTime.UtcNow;
        if (id.FirstSeenUtc == default) id.FirstSeenUtc = id.LastSeenUtc;
        if (!string.IsNullOrEmpty(effectivePath)) id.Paths.Add(effectivePath);
        if (string.IsNullOrEmpty(id.DisplayName))
            id.DisplayName = string.IsNullOrEmpty(e.Description) ? e.Name : e.Description;

        if (key.StartsWith("sig:", StringComparison.Ordinal))
        {
            id.Kind = IdentityKind.Signed;
            id.CertSubject ??= e.SignatureSubject;
        }
        else if (key.StartsWith("path:", StringComparison.Ordinal))
            id.Kind = IdentityKind.PathOnly;
        else if (key.StartsWith("sys:", StringComparison.Ordinal))
            id.Kind = IdentityKind.SystemReserved;
    }

    /// 从命令行提取 exe 路径：引号优先，否则取首个空格前
    private static string? ExtractExePath(string? cmd)
    {
        if (string.IsNullOrWhiteSpace(cmd)) return null;
        cmd = cmd.Trim();
        if (cmd.StartsWith('"'))
        {
            int q = cmd.IndexOf('"', 1);
            return q > 1 ? cmd[1..q] : null;
        }
        int sp = cmd.IndexOf(' ');
        return sp > 0 ? cmd[..sp] : cmd;
    }

    /// 身份键派生：签名（CN+产品名）优先，路径哈希兜底；PID 复用/签名变化自动重算
    private string IdentityKeyFor(int pid, string? path, SignatureState sig, string? subject, string? productName, string name)
    {
        if (pid == 0) return "sys:idle";
        if (pid == 4) return "sys:kernel";

        string sigKey = $"{sig}|{subject}|{productName}|{path}";
        if (_identityCache.TryGetValue(pid, out var cached) && cached.Sig == sigKey)
            return cached.Key;

        string key;
        if (!string.IsNullOrEmpty(path))
        {
            if (sig is SignatureState.Valid or SignatureState.Untrusted or SignatureState.Invalid
                && !string.IsNullOrEmpty(subject))
            {
                var product = string.IsNullOrEmpty(productName) ? name : productName!;
                key = $"sig:{IdentityUtil.ShortHash(subject + "|" + product)}";
            }
            else
            {
                key = $"path:{IdentityUtil.ShortHash(path.ToLowerInvariant())}";
            }
        }
        else
        {
            key = $"unk:{pid}";
        }

        _identityCache[pid] = (sigKey, path ?? "", key);
        return key;
    }

    /// ETW 内核 Process 事件（含启动 rundown）：补父进程与命令行
    public void ApplyKernelProcessEvent(bool isStart, int pid, int? parentPid, string? image, string? cmdLine, DateTime utc)
    {
        var inst = _processes.GetOrAdd(pid, _ => new ProcessInstance { Pid = pid });
        if (isStart)
        {
            if (parentPid != null) inst.ParentPid = parentPid;
            if (!string.IsNullOrEmpty(cmdLine)) inst.CommandLine = cmdLine;
            if (!string.IsNullOrEmpty(image) && inst.Path == null) inst.Path = image;
            inst.ExitTimeUtc = null;
        }
        else
        {
            inst.ExitTimeUtc = utc;
        }
    }

    // ---------- 目的地 ----------

    public DestinationEntity NoteDestination(string? domain, string ip, DateTime utc)
    {
        string key = string.IsNullOrEmpty(domain) ? $"ip:{ip}" : $"d:{domain.ToLowerInvariant()}";
        var d = _destinations.GetOrAdd(key, _ => new DestinationEntity { Key = key, Domain = domain });
        if (!string.IsNullOrEmpty(ip)) d.Ips.Add(ip);
        d.LastSeenUtc = utc;
        if (d.FirstSeenUtc == default) d.FirstSeenUtc = utc;
        return d;
    }

    public DestinationEntity? DestinationByKey(string key) =>
        _destinations.TryGetValue(key, out var d) ? d : null;

    public DestinationEntity? DestinationForIp(string ip) =>
        _destinations.Values.FirstOrDefault(d => d.Ips.Contains(ip));

    // ---------- 服务 ----------

    // ---------- 关系（身份 → 目的地）：P3 基线记账的增量源 ----------

    public sealed class RelationDelta
    {
        public long CountDelta;
        public long UpDelta;
        public long DownDelta;
        public DateTime FirstSeenUtc = DateTime.UtcNow;
        public DateTime LastSeenUtc = DateTime.UtcNow;
    }

    private readonly ConcurrentDictionary<string, ConcurrentDictionary<string, RelationDelta>> _relations =
        new(StringComparer.OrdinalIgnoreCase);

    public void NoteIdentityDestTraffic(string identityKey, string destKey, bool isSend, long bytes, DateTime utc)
    {
        if (identityKey.StartsWith("unk:", StringComparison.Ordinal) || string.IsNullOrEmpty(destKey)) return;
        var rel = _relations.GetOrAdd(identityKey, _ =>
            new ConcurrentDictionary<string, RelationDelta>(StringComparer.OrdinalIgnoreCase));
        if (!rel.ContainsKey(destKey) && rel.Count >= 500) return; // 单身份目的地软上限
        var d = rel.GetOrAdd(destKey, _ => new RelationDelta());
        if (isSend) Interlocked.Add(ref d.UpDelta, bytes);
        else Interlocked.Add(ref d.DownDelta, bytes);
        Interlocked.Increment(ref d.CountDelta);
        d.LastSeenUtc = utc;
    }

    /// 取走本周期增量并清零（UI 线程调用，与写入线程同源无竞争）
    public List<RelationRow> DrainRelationDeltas()
    {
        var list = new List<RelationRow>();
        foreach (var kv in _relations)
            foreach (var kv2 in kv.Value)
            {
                var d = kv2.Value;
                long c = Interlocked.Exchange(ref d.CountDelta, 0);
                long u = Interlocked.Exchange(ref d.UpDelta, 0);
                long dn = Interlocked.Exchange(ref d.DownDelta, 0);
                if (c == 0 && u == 0 && dn == 0) continue;
                list.Add(new RelationRow(kv.Key, kv2.Key, c, u, dn, d.FirstSeenUtc, d.LastSeenUtc));
            }
        return list;
    }

    /// 每 30 秒调用一次：枚举系统服务并按 PID 归组
    public void RefreshServices()
    {
        var list = ServiceControl.EnumServices();
        if (list.Count == 0) return; // 枚举失败保留旧数据

        var byPid = new Dictionary<int, List<ServiceEntity>>();
        foreach (var s in list)
        {
            if (s.Pid <= 0) continue;
            var ent = _services.GetOrAdd(s.Name, _ => new ServiceEntity { Name = s.Name, DisplayName = s.DisplayName });
            ent.DisplayName = s.DisplayName;
            ent.Pids.Add(s.Pid);
            if (!byPid.TryGetValue(s.Pid, out var l)) byPid[s.Pid] = l = new List<ServiceEntity>();
            l.Add(ent);
        }
        _servicesByPid = byPid;
    }
}
