using System.Collections.Concurrent;
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

    /// 由 ProcessTracker 的解析结果登记/刷新进程实例，并派生软件身份
    public void ApplyProcessEntry(ProcessEntry e)
    {
        var inst = _processes.GetOrAdd(e.Pid, _ => new ProcessInstance { Pid = e.Pid });
        inst.Name = e.Name;
        inst.Path = e.Path;
        inst.StartTimeUtc ??= e.StartTimeUtc;
        if (e.Exited) inst.ExitTimeUtc ??= DateTime.UtcNow;

        var key = IdentityKeyFor(e);
        inst.IdentityKey = key;
        var id = _identities.GetOrAdd(key, _ => new SoftwareIdentity { Key = key });
        id.LastSeenUtc = DateTime.UtcNow;
        if (id.FirstSeenUtc == default) id.FirstSeenUtc = id.LastSeenUtc;
        if (!string.IsNullOrEmpty(e.Path)) id.Paths.Add(e.Path!);
        if (string.IsNullOrEmpty(id.DisplayName))
            id.DisplayName = string.IsNullOrEmpty(e.Description) ? e.Name : e.Description;

        switch (key)
        {
            case var k when k.StartsWith("sig:", StringComparison.Ordinal):
                id.Kind = IdentityKind.Signed;
                id.CertSubject = e.SignatureSubject;
                break;
            case var k when k.StartsWith("path:", StringComparison.Ordinal):
                id.Kind = IdentityKind.PathOnly;
                break;
            case var k when k.StartsWith("sys:", StringComparison.Ordinal):
                id.Kind = IdentityKind.SystemReserved;
                break;
        }
        if (e.SignatureSubject != null) id.CertSubject ??= e.SignatureSubject;
    }

    /// 身份键派生：签名（CN+产品名）优先，路径哈希兜底；PID 复用/签名变化自动重算
    public string IdentityKeyFor(ProcessEntry e)
    {
        if (e.Pid == 0) return "sys:idle";
        if (e.Pid == 4) return "sys:kernel";

        string sig = $"{e.Signature}|{e.SignatureSubject}|{e.ProductName}|{e.Path}";
        if (_identityCache.TryGetValue(e.Pid, out var cached) && cached.Sig == sig)
            return cached.Key;

        string key;
        if (!string.IsNullOrEmpty(e.Path))
        {
            if (e.Signature is SignatureState.Valid or SignatureState.Untrusted or SignatureState.Invalid
                && !string.IsNullOrEmpty(e.SignatureSubject))
            {
                var product = string.IsNullOrEmpty(e.ProductName) ? e.Name : e.ProductName!;
                key = $"sig:{IdentityUtil.ShortHash(e.SignatureSubject + "|" + product)}";
            }
            else
            {
                key = $"path:{IdentityUtil.ShortHash(e.Path.ToLowerInvariant())}";
            }
        }
        else
        {
            key = $"unk:{e.Pid}";
        }

        _identityCache[e.Pid] = (sig, e.Path ?? "", key);
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
