using System.Collections.Concurrent;
using System.Diagnostics;
using System.Threading.Channels;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using NetWatch.Models;
using NetWatch.Native;

namespace NetWatch.Services;

/// PID → 进程元信息（名称/路径/图标/厂商/签名）。解析在后台线程进行，绝不阻塞事件链路。
public sealed class ProcessTracker : IDisposable
{
    private readonly ConcurrentDictionary<int, ProcessEntry> _entries = new();
    private readonly ConcurrentDictionary<string, byte> _resolvedPaths = new(StringComparer.OrdinalIgnoreCase);
    private readonly Channel<int> _queue = Channel.CreateUnbounded<int>(new UnboundedChannelOptions { SingleReader = true });
    private readonly CancellationTokenSource _cts = new();

    public ProcessTracker()
    {
        Task.Run(() => ResolveLoop(_cts.Token));
    }

    public ProcessEntry Get(int pid)
    {
        // 拦截异常 PID（个别事件的脏数据），不进解析队列，避免打死后台线程
        if (pid == 0 || pid == 4 || pid < 0 || pid > 8_000_000)
        {
            return new ProcessEntry
            {
                Pid = pid,
                Name = pid == 4 ? "System（内核）" : pid == 0 ? "Idle" : $"PID {pid}",
                Exited = !(pid == 0 || pid == 4), // 系统保留 PID 是常驻的；脏数据行让其自然过期
            };
        }

        return _entries.GetOrAdd(pid, p =>
        {
            var entry = new ProcessEntry
            {
                Pid = p,
                Name = $"PID {p}"
            };
            _queue.Writer.TryWrite(p);
            return entry;
        });
    }

    private async Task ResolveLoop(CancellationToken ct)
    {
        var reader = _queue.Reader;
        while (await reader.WaitToReadAsync(ct))
        {
            while (reader.TryRead(out var pid))
            {
                try { SafeResolve(pid); }
                catch (Exception ex) { Log.Error($"解析进程 {pid} 失败", ex); }
            }
        }
    }

    private void SafeResolve(int pid)
    {
        if (!_entries.TryGetValue(pid, out var entry)) return;
        try
        {
            using var p = Process.GetProcessById(pid);
            entry.Name = p.ProcessName;
            try { entry.StartTimeUtc = p.StartTime.ToUniversalTime(); } catch { }
            try { entry.Path = p.MainModule?.FileName; } catch { }

            if (!string.IsNullOrEmpty(entry.Path) && _resolvedPaths.TryAdd(entry.Path!, 0))
            {
                try
                {
                    var fvi = FileVersionInfo.GetVersionInfo(entry.Path!);
                    entry.Company = Blank(fvi.CompanyName);
                    entry.Description = Blank(fvi.FileDescription);
                }
                catch { }
                entry.Icon = LoadIcon(entry.Path!);
            }

            if (!string.IsNullOrEmpty(entry.Path))
            {
                var (state, subject) = Authenticode.Verify(entry.Path!);
                entry.Signature = state;
                entry.SignatureSubject = subject;
            }

            entry.Exited = false;
            entry.LastActivityUtc = DateTime.UtcNow;
        }
        catch (ArgumentException)
        {
            entry.Exited = true; // 进程已不存在
        }
        catch
        {
            // 权限不足 / 受保护进程：保留占位信息
        }
    }

    private static string? Blank(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();

    private static ImageSource? LoadIcon(string path)
    {
        try
        {
            var h = NativeMethods.GetFileIconHandle(path);
            if (h == IntPtr.Zero) return null;
            try
            {
                var src = Imaging.CreateBitmapSourceFromHIcon(h, Int32Rect.Empty, BitmapSizeOptions.FromEmptyOptions());
                src.Freeze();
                return src;
            }
            finally { NativeMethods.FreeIconHandle(h); }
        }
        catch { return null; }
    }

    public void Dispose()
    {
        try { _cts.Cancel(); } catch { }
    }
}
