using System.Diagnostics;
using System.Text.RegularExpressions;

namespace NetWatch.Services;

public sealed record WifiInfo(string Ssid, int SignalPct, string RxRate, string TxRate);

/// 通过 netsh wlan show interfaces 读取 Wi-Fi 状态（信号强度 / SSID / 收发速率）。
/// 仅在用户点击"网络体检"时调用；无 Wi-Fi 或解析失败返回 null。
public static class WifiProbe
{
    public static WifiInfo? GetConnectedWifi()
    {
        try
        {
            var psi = new ProcessStartInfo("netsh.exe")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
            };
            psi.ArgumentList.Add("wlan");
            psi.ArgumentList.Add("show");
            psi.ArgumentList.Add("interfaces");
            using var p = Process.Start(psi)!;
            var output = p.StandardOutput.ReadToEnd();
            p.WaitForExit(5000);
            if (p.ExitCode != 0) return null;

            // 找到"已连接"状态的接口块（按空行分块）
            foreach (var block in Regex.Split(output, @"\r?\n\s*\r?\n"))
            {
                if (!block.Contains("已连接") && !block.Contains("Connected", StringComparison.OrdinalIgnoreCase)) continue;

                string? Get(string[] keys)
                {
                    foreach (var line in block.Split('\n'))
                    {
                        foreach (var key in keys)
                            if (line.Contains(key, StringComparison.OrdinalIgnoreCase))
                            {
                                var idx = line.LastIndexOf(':');
                                if (idx >= 0) return line[(idx + 1)..].Trim();
                            }
                    }
                    return null;
                }

                var ssid = Get(new[] { " SSID", " SSID" });
                if (string.IsNullOrEmpty(ssid) || ssid == "--") continue; // 未连接热点的接口块

                var signal = 0;
                var signalLine = Get(new[] { "信号", "Signal" });
                var m = Regex.Match(signalLine ?? "", @"(\d+)\s*%");
                if (m.Success) signal = int.Parse(m.Groups[1].Value);

                var rx = Get(new[] { "接收速率", "Receive rate" }) ?? "—";
                var tx = Get(new[] { "传输速率", "Transmit rate" }) ?? "—";
                return new WifiInfo(ssid, signal, rx, tx);
            }
            return null;
        }
        catch (Exception ex) { Log.Error("Wi-Fi 状态读取失败", ex); return null; }
    }
}
