using System.Collections.Concurrent;
using System.IO;
using System.Text.Json;
using NetWatch.Models;

namespace NetWatch.Services;

/// 原始证据流（JSONL，按天滚动）：告警相关 + 新连接 + 大额传输 + DNS + 进程生命周期。
/// 写一次永不改，崩溃最多丢最后一行；保留天数与容量上限由用户设置。
public sealed class EvidenceWriter
{
    private readonly AppSettings _settings;
    private readonly ConcurrentQueue<string> _lines = new();
    private StreamWriter? _writer;
    private string _currentDay = "";

    public EvidenceWriter(AppSettings settings)
    {
        _settings = settings;
        try { Directory.CreateDirectory(AppSettings.EvidenceDir); } catch { }
    }

    public void Enqueue(EventRecord e)
    {
        var dto = new
        {
            t = e.TimeUtc.ToString("o"),
            k = EventRecord.KindText(e.Kind),
            pid = e.Pid,
            ip = e.RemoteIp,
            port = e.RemotePort,
            proto = e.Proto.ToString(),
            bytes = e.Bytes,
            domain = e.Domain,
            level = (int)e.Level,
            text = e.Text,
        };
        _lines.Enqueue(JsonSerializer.Serialize(dto));
    }

    /// UI 线程每秒调用：落盘队列，按天滚动文件
    public void FlushIfDue()
    {
        try
        {
            if (_lines.IsEmpty) return;
            var day = DateTime.UtcNow.ToString("yyyy-MM-dd");
            if (_writer == null || day != _currentDay)
            {
                _writer?.Dispose();
                _currentDay = day;
                _writer = new StreamWriter(
                    new FileStream(Path.Combine(AppSettings.EvidenceDir, $"{day}.jsonl"),
                        FileMode.Append, FileAccess.Write, FileShare.Read)) { AutoFlush = true };
            }
            while (_lines.TryDequeue(out var line))
                _writer.WriteLine(line);
        }
        catch (Exception ex) { Log.Error("证据流写入失败", ex); }
    }

    /// 删除超期文件 + 容量硬顶兜底（最旧先删）
    public void Cleanup()
    {
        try
        {
            var dir = new DirectoryInfo(AppSettings.EvidenceDir);
            if (!dir.Exists) return;
            int keepDays = _settings.EvidenceRetentionDays;
            var cutoff = DateTime.UtcNow.AddDays(-Math.Max(1, keepDays));
            var files = dir.GetFiles("*.jsonl").OrderBy(f => f.Name).ToList();

            foreach (var f in files.Where(f => f.LastWriteTimeUtc < cutoff).ToList())
            {
                f.Delete();
                files.Remove(f);
            }

            long capBytes = (long)_settings.EvidenceMaxSizeMB * 1024 * 1024;
            while (files.Sum(f => f.Length) > capBytes && files.Count > 1)
            {
                files[0].Delete();
                files.RemoveAt(0);
            }
        }
        catch (Exception ex) { Log.Error("证据流清理失败", ex); }
    }

    public (long Bytes, int Files) Stats()
    {
        try
        {
            var dir = new DirectoryInfo(AppSettings.EvidenceDir);
            if (!dir.Exists) return (0, 0);
            var files = dir.GetFiles("*.jsonl");
            return (files.Sum(f => f.Length), files.Length);
        }
        catch { return (0, 0); }
    }
}
