using System.Collections.Concurrent;
using NetWatch.Models;

namespace NetWatch.Services;

public sealed class PidStats
{
    public long UpTotal, DownTotal;      // 会话累计（字节）
    public long UpWindow, DownWindow;    // 本 tick 窗口
    public double UpSpeed, DownSpeed;    // EMA 平滑速率（字节/秒）
    public DateTime LastActivityUtc = DateTime.UtcNow;
}

public sealed class RemoteStats
{
    public long Up, Down;
    public DateTime FirstUtc = DateTime.UtcNow;
    public DateTime LastUtc = DateTime.UtcNow;
    public HashSet<int> Pids = new();
}

/// 消费 ETW 网络事件：每进程 ↑↓ 速率/累计 + 按远端 IP 聚合 + 大额传输标记
public sealed class RateAggregator
{
    private readonly ConcurrentDictionary<int, PidStats> _stats = new();
    private readonly ConcurrentDictionary<string, RemoteStats> _remotes = new();
    private readonly ConcurrentQueue<NetEvent> _queue = new();
    private readonly ConcurrentQueue<NetEvent> _logQueue = new();
    private long _eventCount;

    public const long LargeTransferBytes = 1_000_000;

    public IReadOnlyDictionary<int, PidStats> Stats => _stats;
    public IReadOnlyDictionary<string, RemoteStats> Remotes => _remotes;
    public long EventCount => Interlocked.Read(ref _eventCount);

    public void Enqueue(NetEvent e)
    {
        Interlocked.Increment(ref _eventCount);
        switch (e.Kind)
        {
            case EventKind.Traffic:
                _queue.Enqueue(e);
                if (e.Bytes >= LargeTransferBytes) _logQueue.Enqueue(e);
                break;
            case EventKind.NewConn:
            case EventKind.Closed:
                _logQueue.Enqueue(e);
                break;
        }
    }

    /// UI 线程每秒调用：清空队列、推进速率窗口。logSink 收到本秒需要记入事件流的条目。
    public void Tick(bool includeLoopback, List<NetEvent> logSink)
    {
        while (_logQueue.TryDequeue(out var le)) logSink.Add(le);

        while (_queue.TryDequeue(out var e))
        {
            if (!includeLoopback && e.IsLoopback) continue;

            var s = _stats.GetOrAdd(e.Pid, _ => new PidStats());
            if (e.IsSend) { s.UpWindow += e.Bytes; s.UpTotal += e.Bytes; }
            else { s.DownWindow += e.Bytes; s.DownTotal += e.Bytes; }
            s.LastActivityUtc = e.TimeUtc;

            if (!string.IsNullOrEmpty(e.RemoteIp))
            {
                var r = _remotes.GetOrAdd(e.RemoteIp!, _ => new RemoteStats());
                if (e.IsSend) r.Up += e.Bytes; else r.Down += e.Bytes;
                r.LastUtc = e.TimeUtc;
                lock (r.Pids)
                {
                    r.Pids.Add(e.Pid);
                    if (r.Pids.Count > 24) r.Pids.Remove(r.Pids.First());
                }
            }
        }

        foreach (var s in _stats.Values)
        {
            s.UpSpeed = s.UpSpeed * 0.5 + s.UpWindow * 0.5;
            s.DownSpeed = s.DownSpeed * 0.5 + s.DownWindow * 0.5;
            s.UpWindow = 0;
            s.DownWindow = 0;
        }
    }

    /// 暂停监控时丢弃积压事件
    public void Drain()
    {
        while (_queue.TryDequeue(out _)) { }
        while (_logQueue.TryDequeue(out _)) { }
    }

    /// PID 复用 / 手动重置
    public void ResetPid(int pid) => _stats.TryRemove(pid, out _);

    /// 远端聚合裁剪：只保留最近活跃的
    public void PruneRemotes(TimeSpan maxAge)
    {
        var cutoff = DateTime.UtcNow - maxAge;
        foreach (var kv in _remotes)
            if (kv.Value.LastUtc < cutoff)
                _remotes.TryRemove(kv.Key, out _);
    }
}
