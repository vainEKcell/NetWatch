using NetWatch.Models;

namespace NetWatch.Services;

/// 统一事件库：所有可观测事件（连接/DNS/大额传输/配置/提示/进程生命周期）的内存环形存储。
/// 页面是它的视图；P2 的证据链、P3 的持久化都从这里取料。
public sealed class EventStore
{
    private readonly object _gate = new();
    private readonly EventRecord[] _ring = new EventRecord[65536];
    private long _seq;

    public long TotalCount => Interlocked.Read(ref _seq);

    public EventRecord Add(EventRecord e)
    {
        lock (_gate)
        {
            e = e with { Seq = _seq };
            _ring[_seq % _ring.Length] = e;
            _seq++;
        }
        return e;
    }

    /// 通用查询：按谓词过滤，返回时间倒序、最多 max 条
    public List<EventRecord> Query(Func<EventRecord, bool>? predicate = null, int max = 500)
    {
        var result = new List<EventRecord>();
        lock (_gate)
        {
            long start = Math.Max(0, _seq - _ring.Length);
            for (long i = _seq - 1; i >= start && result.Count < max; i--)
            {
                var e = _ring[i % _ring.Length];
                if (e == null) continue;
                if (predicate == null || predicate(e)) result.Add(e);
            }
        }
        return result;
    }

    /// 调查视图核心：与给定实体相关的全部事件（进程/身份/目标/域名/时间窗）
    public List<EventRecord> QueryRelated(
        int? pid = null, string? identityKey = null, string? remoteIp = null,
        string? domain = null, TimeSpan? window = null, int max = 500)
    {
        DateTime cutoff = window == null ? DateTime.MinValue : DateTime.UtcNow - window.Value;
        return Query(e =>
        {
            if (e.TimeUtc < cutoff) return false;
            if (pid != null && e.Pid == pid.Value) return true;
            if (identityKey != null && e.IdentityKey == identityKey) return true;
            if (remoteIp != null && string.Equals(e.RemoteIp, remoteIp, StringComparison.OrdinalIgnoreCase)) return true;
            if (domain != null && string.Equals(e.Domain, domain, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }, max);
    }
}
