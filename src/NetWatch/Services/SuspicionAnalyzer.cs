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
                Add(RiskLevel.High, $"进程名「{name}」与系统进程相同，但运行在非系统目录——常见伪装手法");

            switch (e.Signature)
            {
                case SignatureState.Invalid:
                    Add(RiskLevel.High, "数字签名无效——文件在签名后可能被篡改");
                    break;
                case SignatureState.Untrusted:
                    Add(RiskLevel.Medium, "签名证书不受信任（自签名或未知发布者）");
                    break;
                case SignatureState.Unsigned when InSuspiciousDir(lower):
                    Add(RiskLevel.Medium, "位于临时/下载类目录且未签名");
                    break;
                case SignatureState.Unsigned:
                    Add(RiskLevel.Low, "程序未签名");
                    break;
            }

            if (InSuspiciousDir(lower) && e.Signature is not (SignatureState.Unsigned or SignatureState.Invalid))
                Add(RiskLevel.Low, "运行于临时/下载类目录");
        }

        if (s != null && sessionLen > TimeSpan.FromSeconds(60))
        {
            if (s.DownTotal > 0 && s.UpTotal > s.DownTotal * 3 && s.UpTotal > 30_000_000)
                Add(RiskLevel.Medium, $"上传量({Util.FormatBytes(s.UpTotal)})远大于下载量({Util.FormatBytes(s.DownTotal)})——疑似数据外传");
            if (sessionLen < TimeSpan.FromSeconds(180) && s.UpTotal > 20_000_000)
                Add(RiskLevel.Medium, "新出现的程序短时间内大量上传");
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
