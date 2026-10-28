using System.Net;
using System.Net.NetworkInformation;
using NetWatch.Models;

namespace NetWatch.Services;

public sealed record PingProbeResult(string Target, int Sent, int Ok, double MinMs, double AvgMs, double MaxMs, double JitterMs, double LossPct);

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

        double min = 0, avg = 0, max = 0, jitter = 0;
        if (latencies.Count > 0)
        {
            min = latencies.Min();
            max = latencies.Max();
            avg = latencies.Average();
            if (latencies.Count > 1)
                jitter = latencies.Zip(latencies.Skip(1), (a, b) => Math.Abs(a - b)).Average();
        }

        return new PingProbeResult(target, count, latencies.Count, min, avg, max, jitter,
            (count - latencies.Count) * 100.0 / count);
    }
}
