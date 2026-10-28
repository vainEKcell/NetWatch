using System.Net;
using System.Net.NetworkInformation;
using NetWatch.Models;

namespace NetWatch.Services;

public sealed record PingProbeResult(string Target, int Sent, int Ok, double MinMs, double AvgMs, double MaxMs, double JitterMs, double LossPct, double P95Ms)
{
    /// P95 延迟的单数档评定（0=优秀 1=一般 2=较差），供综合评级使用
    public int QualityScore => LossPct >= 2 || AvgMs >= 80 ? 2 : LossPct > 0 || AvgMs >= 40 || P95Ms >= 150 ? 1 : 0;
}

/// 延迟 / 抖动 / 丢包探测：对目标连发 ping，统计 min/avg/max、相邻差值均值的抖动、丢包率。
public static class PingProbe
{
    public static async Task<PingProbeResult> RunAsync(string target, int count, CancellationToken ct)
    {
        using var ping = new Ping();
        var latencies = new List<double>();

        for (int i = 0; i < count; i++)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                var reply = await ping.SendPingAsync(target, 1000);
                if (reply.Status == IPStatus.Success)
                    latencies.Add(reply.RoundtripTime);
            }
            catch { /* 单发失败计入丢包 */ }
            try { await Task.Delay(250, ct); } catch (OperationCanceledException) { }
        }

        double min = 0, avg = 0, max = 0, jitter = 0, p95 = 0;
        if (latencies.Count > 0)
        {
            min = latencies.Min();
            max = latencies.Max();
            avg = latencies.Average();
            if (latencies.Count > 1)
                jitter = latencies.Zip(latencies.Skip(1), (a, b) => Math.Abs(a - b)).Average();
            var sorted = latencies.OrderBy(x => x).ToList();
            p95 = sorted[Math.Min(sorted.Count - 1, (int)Math.Ceiling(sorted.Count * 0.95) - 1)];
        }

        return new PingProbeResult(target, count, latencies.Count, min, avg, max, jitter,
            (count - latencies.Count) * 100.0 / count, p95);
    }

    /// 路径 MTU 探测：带 DF 标志从 1472 字节（1500 MTU 标准负载）向下试探，
    /// 返回最大可通过负载 + 28（IP 头）≈ 路径 MTU。PPPoE/VPN 环境会明显偏低。
    public static async Task<int?> ProbeMtuAsync(string target, CancellationToken ct)
    {
        using var ping = new Ping();
        for (int size = 1472; size >= 1300; size -= 10)
        {
            for (int attempt = 0; attempt < 2; attempt++)
            {
                try
                {
                    var reply = await ping.SendPingAsync(target, 1200, new byte[size], new PingOptions(64, true));
                    if (reply.Status == IPStatus.Success) return size + 28;
                    if (reply.Status == IPStatus.TimedOut) break; // DF 大包被静默丢弃，继续缩小
                }
                catch (OperationCanceledException) { throw; }
                catch { }
            }
            ct.ThrowIfCancellationRequested();
        }
        return null;
    }
}
