using System.IO;
using NetWatch.Models;
using NetWatch.Services;

/// 分析引擎（P2）：规则只产出证据，聚合后定级。
/// 原则：单因素最高 Attention；HighRisk 必须多项独立特征组合；证据不足输出 Unknown。
/// 处置层（P5）：用户加入允许名单的软件身份，其信任决定优先于引擎判定。
/// 文案经 L10n 本地化（zh/en）。
public static class AnalysisEngine
{
    public static Verdict Evaluate(ProcessEntry e, PidStats? s, TimeSpan sessionLen, bool userTrusted = false)
    {
        var v = new Verdict();

        // ---------- 1. 身份与位置类证据 ----------
        var path = e.Path;
        bool inSuspiciousDir = false;

        if (!string.IsNullOrEmpty(path))
        {
            var lower = path!.ToLowerInvariant();
            var name = Path.GetFileName(lower);
            string winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows).ToLowerInvariant();
            string sysDir = Environment.SystemDirectory.ToLowerInvariant();
            bool underSystem = lower.StartsWith(sysDir) || lower.StartsWith($"{winDir}\\syswow64");
            inSuspiciousDir = InSuspiciousDir(lower);

            if (SysNames.Contains(name) && !underSystem)
                v.Evidence.Add(new EvidenceItem(
                    L10n.T("eng.masquerade", name, path),
                    L10n.T("eng.masquerade.basis"),
                    L10n.T("eng.masquerade.caveat"), 3));

            switch (e.Signature)
            {
                case SignatureState.Invalid:
                    v.Evidence.Add(new EvidenceItem(
                        L10n.T("eng.sigInvalid"),
                        L10n.T("eng.sigInvalid.basis", path),
                        L10n.T("eng.sigInvalid.caveat"), 3));
                    break;
                case SignatureState.Untrusted:
                    v.Evidence.Add(new EvidenceItem(
                        L10n.T("eng.sigUntrusted"),
                        L10n.T("eng.sigUntrusted.basis", e.SignatureSubject ?? ""),
                        L10n.T("eng.sigUntrusted.caveat"), 2));
                    break;
                case SignatureState.Unsigned when inSuspiciousDir:
                    v.Evidence.Add(new EvidenceItem(
                        L10n.T("eng.unsignedTemp"),
                        L10n.T("eng.dir.basis", path),
                        L10n.T("eng.unsignedTemp.caveat"), 2));
                    break;
                case SignatureState.Unsigned:
                    v.Evidence.Add(new EvidenceItem(
                        L10n.T("eng.unsigned"),
                        L10n.T("eng.dir.basis", path),
                        L10n.T("eng.unsigned.caveat"), 1));
                    break;
            }

            if (inSuspiciousDir && e.Signature is not (SignatureState.Unsigned or SignatureState.Invalid))
                v.Evidence.Add(new EvidenceItem(
                    L10n.T("eng.signedTemp"),
                    L10n.T("eng.dir.basis", path),
                    L10n.T("eng.signedTemp.caveat"), 1));
        }

        // ---------- 2. 行为类证据（数据量是证据但不能孤立判断） ----------
        if (s != null && sessionLen > TimeSpan.FromSeconds(60))
        {
            if (s.DownTotal > 0 && s.UpTotal > s.DownTotal * 3 && s.UpTotal > 30_000_000)
                v.Evidence.Add(new EvidenceItem(
                    L10n.T("eng.uploadRatio", Util.FormatBytes(s.UpTotal), Util.FormatBytes(s.DownTotal),
                        s.UpTotal / Math.Max(1, s.DownTotal)),
                    L10n.T("eng.uploadRatio.basis"),
                    L10n.T("eng.uploadRatio.caveat"), 2));

            if (sessionLen < TimeSpan.FromSeconds(180) && s.UpTotal > 20_000_000)
            {
                bool wellAnchored = e.Signature == SignatureState.Valid
                    && !string.IsNullOrEmpty(path)
                    && (path!.Contains("\\Program Files", StringComparison.OrdinalIgnoreCase)
                        || path.Contains("\\Windows\\", StringComparison.OrdinalIgnoreCase));
                v.Evidence.Add(new EvidenceItem(
                    L10n.T("eng.newBurst", Util.FormatBytes(s.UpTotal)),
                    L10n.T("eng.newBurst.basis", sessionLen.TotalSeconds),
                    L10n.T(wellAnchored ? "eng.newBurst.caveatOk" : "eng.newBurst.caveatBad"),
                    wellAnchored ? 1 : 2));
            }
        }

        // ---------- 3. 处置层：用户信任优先 ----------
        if (userTrusted)
        {
            v.Status = VerdictStatus.Normal;
            v.Summary = L10n.T("eng.trustedSummary");
            v.Evidence.Add(new EvidenceItem(
                L10n.T("eng.trustedItem", v.Evidence.Count),
                L10n.T("eng.trustedItem.basis"),
                null, 1));
            return v;
        }

        // ---------- 4. 聚合定级 ----------
        int strong = v.Evidence.Count(x => x.Weight >= 3);
        int mid = v.Evidence.Count(x => x.Weight == 2);
        int total = v.Evidence.Sum(x => x.Weight);

        if (strong >= 1 && v.Evidence.Count >= 2 && strong + mid >= 2)
        {
            v.Status = VerdictStatus.HighRisk;
            v.Summary = L10n.T("eng.highSummary", v.Evidence.Count, strong);
        }
        else if (total >= 2 || mid >= 1)
        {
            v.Status = VerdictStatus.Attention;
            v.Summary = L10n.T("eng.attentionSummary", v.Evidence.Count);
        }
        else if (v.Evidence.Count == 0 && e.Signature == SignatureState.Valid && !inSuspiciousDir)
        {
            v.Status = VerdictStatus.Normal;
            v.Summary = e.SignatureSubject == null
                ? L10n.T("eng.normalSummary")
                : L10n.T("eng.normalSummarySub", e.SignatureSubject);
        }
        else
        {
            v.Status = VerdictStatus.Unknown;
            v.Summary = L10n.T("eng.unknownSummary");
        }

        return v;
    }

    private static bool InSuspiciousDir(string lowerPath)
    {
        string[] dirs =
        {
            Path.GetTempPath().ToLowerInvariant(),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "temp").ToLowerInvariant(),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "downloads").ToLowerInvariant(),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData).ToLowerInvariant(),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData).ToLowerInvariant(),
        };
        return dirs.Any(d => d.Length > 0 && lowerPath.StartsWith(d));
    }

    private static readonly HashSet<string> SysNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "svchost.exe", "services.exe", "lsass.exe", "lsaiso.exe", "smss.exe", "csrss.exe",
        "wininit.exe", "winlogon.exe", "explorer.exe", "conhost.exe", "dllhost.exe",
        "taskhostw.exe", "spoolsv.exe", "rundll32.exe", "regsvr32.exe", "cmd.exe",
        "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe", "wmiprvse.exe",
        "fontdrvhost.exe", "sihost.exe", "ctfmon.exe", "dwm.exe"
    };
}
