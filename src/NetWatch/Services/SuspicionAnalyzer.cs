using System.IO;
using NetWatch.Models;

namespace NetWatch.Services;

/// 可疑行为启发式。提示 ≠ 确诊病毒，最终解释权在用户。
public static class SuspicionAnalyzer
{
    private static readonly HashSet<string> SysNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "svchost.exe", "services.exe", "lsass.exe", "lsaiso.exe", "smss.exe", "csrss.exe",
        "wininit.exe", "winlogon.exe", "explorer.exe", "conhost.exe", "dllhost.exe",
        "taskhostw.exe", "spoolsv.exe", "rundll32.exe", "regsvr32.exe", "cmd.exe",
        "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe", "wmiprvse.exe",
        "fontdrvhost.exe", "sihost.exe", "ctfmon.exe", "dwm.exe"
    };

    public static void Evaluate(ProcessEntry e, PidStats? s, TimeSpan sessionLen)
    {
        var reasons = new List<string>();
        RiskLevel level = RiskLevel.None;
        void Add(RiskLevel lv, string text) { reasons.Add(text); if (lv > level) level = lv; }

        var path = e.Path;
        if (!string.IsNullOrEmpty(path))
        {
            var lower = path!.ToLowerInvariant();
            var name = Path.GetFileName(lower);
            string winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows).ToLowerInvariant();
            string sysDir = Environment.SystemDirectory.ToLowerInvariant();
            bool underSys = lower.StartsWith(sysDir) || lower.StartsWith($"{winDir}\\syswow64");

            if (SysNames.Contains(name) && !underSys)
                Add(RiskLevel.High, $"观察到：进程名「{name}」与系统进程相同，但运行于非系统目录（{path}）。依据：合法系统进程固定位于系统目录；缺失：签名归属。建议核查该文件");

            switch (e.Signature)
            {
                case SignatureState.Invalid:
                    Add(RiskLevel.High, $"观察到：文件数字签名校验失败（{path}）。依据：签名内容与文件不匹配；可能原因：文件在签名后被篡改，或已知软件被重打包。建议核查");
                    break;
                case SignatureState.Untrusted:
                    Add(RiskLevel.Medium, $"观察到：签名证书不受系统信任（{(e.SignatureSubject ?? "未知发布者")}）。可能原因：自签名证书的开源/个人软件。本身不构成风险结论");
                    break;
                case SignatureState.Unsigned when InSuspiciousDir(lower):
                    Add(RiskLevel.Medium, $"观察到：未签名程序运行于临时/下载类目录（{path}）。依据：恶意软件常见落位；误报可能：用户自行下载的绿色工具");
                    break;
                case SignatureState.Unsigned:
                    Add(RiskLevel.Low, $"观察到：程序未签名（{path}）。说明：大量合法开源软件无签名，此条仅为信息");
                    break;
            }

            if (InSuspiciousDir(lower) && e.Signature is not (SignatureState.Unsigned or SignatureState.Invalid))
                Add(RiskLevel.Low, $"观察到：已签名程序运行于临时/下载类目录（{path}）。误报可能：便携版工具");
        }

        if (s != null && sessionLen > TimeSpan.FromSeconds(60))
        {
            if (s.DownTotal > 0 && s.UpTotal > s.DownTotal * 3 && s.UpTotal > 30_000_000)
                Add(RiskLevel.Medium, $"观察到：会话内上传({Util.FormatBytes(s.UpTotal)})约为下载({Util.FormatBytes(s.DownTotal)})的 {s.UpTotal / Math.Max(1, s.DownTotal)} 倍。误报可能：网盘同步、备份、直播推流、P2P 上传；请结合目的地排行判断数据去向");
            if (sessionLen < TimeSpan.FromSeconds(180) && s.UpTotal > 20_000_000)
            {
                bool wellAnchored = !string.IsNullOrEmpty(e.Path)
                    && e.Signature == SignatureState.Valid
                    && (e.Path!.Contains("\\Program Files", StringComparison.OrdinalIgnoreCase)
                        || e.Path.Contains("\\Windows\\", StringComparison.OrdinalIgnoreCase));
                Add(wellAnchored ? RiskLevel.Low : RiskLevel.Medium,
                    wellAnchored
                        ? $"观察到：已签名的既有位置程序({e.Name})短时间({sessionLen.TotalSeconds:F0}秒)上传 {Util.FormatBytes(s.UpTotal)}。更新器/云盘常见，仅提示"
                        : $"观察到：新出现的程序({e.Name})短时间({sessionLen.TotalSeconds:F0}秒)内上传 {Util.FormatBytes(s.UpTotal)}，且无法通过签名与常规位置佐证。建议查看其目的地与 DNS 记录");
            }
        }

        e.RiskReasons.Clear();
        e.RiskReasons.AddRange(reasons);
        e.Risk = level;
    }

    private static bool InSuspiciousDir(string lowerPath)
    {
        string[] dirs =
        {
            Path.GetTempPath().ToLowerInvariant(),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "temp").ToLowerInvariant(),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "downloads").ToLowerInvariant(),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData).ToLowerInvariant(), // ProgramData
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData).ToLowerInvariant(),        // Roaming
        };
        return dirs.Any(d => d.Length > 0 && lowerPath.StartsWith(d));
    }
}
