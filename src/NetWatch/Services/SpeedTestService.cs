using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text.Json;

namespace NetWatch.Services;

public sealed record SpeedTestResult(string Source, double MbpsAvg, double MbpsPeak, double MBTotal, int Seconds)
{
    public double MBPerSec => MbpsAvg / 8.0;
}

public sealed record IperfResult(bool Ok, double DownMbps, double UpMbps, string Error);

/// 带宽吞吐测速（HTTP 大流量采样）+ iperf3 黄金标准模式。
/// - 下载：从国内公共镜像/CDN 以 HTTP 拉取真实数据 8 秒，剔除前 1 秒 TCP 爬坡期后计算吞吐，多源取最优
/// - 上行：向公共回显端点 POST 随机数据（受接收端限制，标注为参考值）
/// - iperf3：用户自备对端（iperf3 -s），本机作为客户端跑 TCP 上/下行（黄金标准）
public static class SpeedTestService
{
    internal static readonly (string Name, string Url)[] DownloadSources =
    {
        ("华为云镜像", "https://mirrors.huaweicloud.com/ubuntu-releases/24.04/ubuntu-24.04.4-desktop-amd64.iso"),
        ("微信 CDN", "https://dldir1.qq.com/weixin/Windows/WeChatSetup.exe"),
        ("中科大镜像", "https://mirrors.ustc.edu.cn/ubuntu-releases/24.04/ubuntu-24.04.4-desktop-amd64.iso"),
    };

    internal static readonly (string Name, string Url)[] UploadEndpoints =
    {
        ("Cloudflare", "https://speed.cloudflare.com/__up"),
    };

    /// 上次测通的节点下标——下次优先用它（节点可用性随时段变，动态主源 + 顺序备用）
    internal static int LastGoodSource = -1;

    /// 从源池取本次尝试顺序：上次测通的优先，其余按固定顺序兜底
    internal static List<int> SourceOrder()
    {
        var order = new List<int>();
        if (LastGoodSource >= 0 && LastGoodSource < DownloadSources.Length)
            order.Add(LastGoodSource);
        for (int i = 0; i < DownloadSources.Length; i++)
            if (!order.Contains(i)) order.Add(i);
        return order;
    }

    /// 校验目标为公网 https 主机（拒绝 localhost/环回/私有/保留地址）
    public static void ValidatePublicHttps(Uri uri)
    {
        if (uri.Scheme is not ("https" or "http"))
            throw new ArgumentException("仅允许 http/https");
        var host = uri.Host;
        if (IPAddress.TryParse(host, out var direct) && !IsPublicIp(direct))
            throw new ArgumentException("拒绝 localhost/环回/私有/保留地址");
        if (!IPAddress.TryParse(host, out _))
        {
            var addrs = Dns.GetHostAddressesAsync(host).Result;
            if (addrs.Length == 0 || addrs.All(a => !IsPublicIp(a)))
                throw new ArgumentException("主机解析不到公网地址");
        }
    }

    private static bool IsPublicIp(IPAddress ip)
    {
        if (IPAddress.IsLoopback(ip)) return false;
        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            var b = ip.GetAddressBytes();
            if (b[0] == 10 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 192 && b[1] == 168)) return false;
            if (b[0] == 169 && b[1] == 254) return false; // link-local
            if (b[0] == 0 || b[0] >= 224) return false;   // 保留/组播
            if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return false; // CGNAT
            return true;
        }
        return (ip.GetAddressBytes()[0] & 0xFE) != 0xFC; // 排除 ULA fc00::/7
    }

    /// 下载吞吐：Range 拉取真实数据，采样后剔除前 1 秒爬坡期
    public static async Task<SpeedTestResult> RunDownloadAsync(string name, string url, int seconds, CancellationToken ct)
    {
        ValidatePublicHttps(new Uri(url));
        // 测速走直连（不经系统代理），否则测的是代理链路而非本机物理带宽
        using var http = new HttpClient(new HttpClientHandler { UseProxy = false })
        {
            Timeout = TimeSpan.FromSeconds(seconds + 15)
        };
        // 部分镜像站（阿里云等）拒绝无 UA 的客户端
        http.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64) NetWatch/" +
            (typeof(SpeedTestService).Assembly.GetName().Version?.ToString(3) ?? "0.1"));
        http.DefaultRequestHeaders.Range = new System.Net.Http.Headers.RangeHeaderValue(0, 512L * 1024 * 1024);

        var buf = new byte[65536];
        long total = 0;
        var marks = new List<(double Sec, long Bytes)>();
        var start = Stopwatch.GetTimestamp();

        using (var stream = await http.GetStreamAsync(url, ct))
        {
            while (true)
            {
                ct.ThrowIfCancellationRequested();
                var read = await stream.ReadAsync(buf, ct);
                if (read == 0) break;
                total += read;
                var sec = Stopwatch.GetElapsedTime(start).TotalSeconds;
                marks.Add((sec, total));
                if (sec >= seconds) break;
            }
        }

        var duration = Stopwatch.GetElapsedTime(start).TotalSeconds;
        return BuildResult(name, marks, duration, Math.Min(duration, seconds));
    }

    /// 上行吞吐（参考值）：POST 随机数据到回显端点
    public static async Task<SpeedTestResult> RunUploadAsync(string name, string url, int megabytes, CancellationToken ct)
    {
        ValidatePublicHttps(new Uri(url));
        using var http = new HttpClient(new HttpClientHandler { UseProxy = false })
        {
            Timeout = TimeSpan.FromSeconds(120)
        };
        var payload = new byte[megabytes * 1024L * 1024];
        Random.Shared.NextBytes(payload);

        var start = Stopwatch.GetTimestamp();
        using (var content = new ByteArrayContent(payload))
        using (var resp = await http.PostAsync(url, content, ct))
        {
            resp.EnsureSuccessStatusCode();
        }
        var duration = Stopwatch.GetElapsedTime(start).TotalSeconds;

        // 单次整包 POST：吞吐 = 载荷 / 实际用时（回显端点接收能力有限，标注参考值）
        var mbps = payload.Length * 8.0 / duration / 1_000_000;
        return new SpeedTestResult(name, mbps, mbps, payload.Length / 1048576.0, (int)Math.Round(duration));
    }

    private static SpeedTestResult BuildResult(string name, List<(double Sec, long Bytes)> marks, double duration, double countSecs)
    {
        if (marks.Count < 2 || duration < 1.5)
            return new SpeedTestResult(name, 0, 0, marks.Count > 0 ? marks[^1].Bytes / 1048576.0 : 0, (int)Math.Round(duration));

        // 剔除前 1 秒 TCP 爬坡期后的平均吞吐
        var ramp = marks.FirstOrDefault(m => m.Sec >= 1.0);
        double avgMbps;
        if (ramp != default)
        {
            var last = marks[^1];
            avgMbps = (last.Bytes - ramp.Bytes) * 8.0 / ((last.Sec - ramp.Sec) * 1_000_000);
        }
        else
        {
            avgMbps = marks[^1].Bytes * 8.0 / (duration * 1_000_000);
        }

        // 峰值：按 1 秒分桶的最大吞吐（避免把微小块间隔当成噪声过滤掉）
        double peak = 0;
        double bStart = marks[0].Sec;
        long bBytes = marks[0].Bytes;
        for (int i = 1; i < marks.Count; i++)
        {
            var m = marks[i];
            if (m.Sec - bStart >= 1.0)
            {
                peak = Math.Max(peak, (m.Bytes - bBytes) * 8.0 / (m.Sec - bStart) / 1_000_000);
                bStart = m.Sec;
                bBytes = m.Bytes;
            }
        }
        var lastM = marks[^1];
        if (lastM.Sec - bStart > 0.3)
            peak = Math.Max(peak, (lastM.Bytes - bBytes) * 8.0 / (lastM.Sec - bStart) / 1_000_000);

        return new SpeedTestResult(name, avgMbps, peak, marks[^1].Bytes / 1048576.0, (int)Math.Round(duration));
    }
}

/// iperf3 黄金标准模式：调用用户自备的 iperf3.exe 对指定服务器跑 TCP 上/下行
public static class Iperf3Runner
{
    /// 在桌面及常见位置自动寻找 iperf3.exe
    public static string? AutoLocate()
    {
        var desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
        var candidates = new[]
        {
            Path.Combine(desktop, "iperf3.exe"),
            Path.Combine(desktop, "iperf3", "iperf3.exe"),
        };
        foreach (var c in candidates)
            if (File.Exists(c)) return c;

        // 桌面子目录往下搜一层
        try
        {
            foreach (var dir in Directory.GetDirectories(desktop))
            {
                var hit = Path.Combine(dir, "iperf3.exe");
                if (File.Exists(hit)) return hit;
            }
        }
        catch { }
        return null;
    }

    public static async Task<IperfResult> RunAsync(string exePath, string host, int port, int seconds, CancellationToken ct)
    {
        // 先上行（客户端发送），再下行（-R 服务端发送）
        var up = await RunOne(exePath, host, port, seconds, reverse: false, ct);
        var down = await RunOne(exePath, host, port, seconds, reverse: true, ct);
        if (up == null && down == null)
            return new IperfResult(false, 0, 0, "iperf3 未返回有效结果（检查服务器与网络）");
        return new IperfResult(true, down ?? 0, up ?? 0, "");
    }

    private static async Task<double?> RunOne(string exePath, string host, int port, int seconds, bool reverse, CancellationToken ct)
    {
        var psi = new ProcessStartInfo(exePath)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        psi.ArgumentList.Add("-c"); psi.ArgumentList.Add(host);
        psi.ArgumentList.Add("-p"); psi.ArgumentList.Add(port.ToString());
        psi.ArgumentList.Add("-t"); psi.ArgumentList.Add(seconds.ToString());
        if (reverse) psi.ArgumentList.Add("-R");
        psi.ArgumentList.Add("-J");

        using var p = Process.Start(psi)!;
        var stdout = await p.StandardOutput.ReadToEndAsync(ct);
        await p.WaitForExitAsync(ct);
        if (p.ExitCode != 0) return null;

        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(stdout);
            var root = doc.RootElement;
            double bps;
            if (reverse)
                bps = root.GetProperty("end").GetProperty("sum_received").GetProperty("bits_per_second").GetDouble();
            else
                bps = root.GetProperty("end").GetProperty("sum_sent").GetProperty("bits_per_second").GetDouble();
            return bps / 1_000_000.0;
        }
        catch { return null; }
    }
}
