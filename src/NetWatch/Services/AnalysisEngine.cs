using System.IO;
using NetWatch.Models;
using NetWatch.Services;

/// 分析引擎（P2）：规则只产出证据，聚合后定级。
/// 原则：单因素最高 Attention；HighRisk 必须多项独立特征组合；证据不足输出 Unknown。
/// 处置层（P5）：用户加入允许名单的软件身份，其信任决定优先于引擎判定。
public static class AnalysisEngine
{
    public static Verdict Evaluate(ProcessEntry e, PidStats? s, TimeSpan sessionLen, bool userTrusted = false)
    {
        var v = new Verdict();

        // ---------- 1. 身份与位置类证据 ----------
        var path = e.Path;
        bool inSuspiciousDir = false;
        bool underSystem = false;

        if (!string.IsNullOrEmpty(path))
        {
            var lower = path!.ToLowerInvariant();
            var name = Path.GetFileName(lower);
            string winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows).ToLowerInvariant();
            string sysDir = Environment.SystemDirectory.ToLowerInvariant();
            underSystem = lower.StartsWith(sysDir) || lower.StartsWith($"{winDir}\\syswow64");
            inSuspiciousDir = InSuspiciousDir(lower);

            if (SysNames.Contains(name) && !underSystem)
            {
                v.Evidence.Add(new EvidenceItem(
                    $"进程名「{name}」与系统进程相同，但运行于非系统目录（{path}）",
                    "合法系统进程固定位于系统目录",
                    "若用户自行为工具改名则属误报",
                    3));
            }

            switch (e.Signature)
            {
                case SignatureState.Invalid:
                    v.Evidence.Add(new EvidenceItem(
                        "文件数字签名校验失败",
                        $"路径 {path}；签名内容与文件不匹配",
                        "已知软件被重打包/修复也会如此",
                        3));
                    break;
                case SignatureState.Untrusted:
                    v.Evidence.Add(new EvidenceItem(
                        "签名证书不受系统信任",
                        $"签名者：{e.SignatureSubject ?? "未知"}",
                        "自签名证书的开源/个人软件常态",
                        2));
                    break;
                case SignatureState.Unsigned when inSuspiciousDir:
                    v.Evidence.Add(new EvidenceItem(
                        "未签名程序运行于临时/下载类目录",
                        $"路径 {path}",
                        "用户自行下载的绿色工具",
                        2));
                    break;
                case SignatureState.Unsigned:
                    v.Evidence.Add(new EvidenceItem(
                        "程序未签名",
                        $"路径 {path}",
                        "大量合法开源软件无签名；无法建立稳定身份，基线价值降低",
                        1));
                    break;
            }

            if (inSuspiciousDir && e.Signature is not (SignatureState.Unsigned or SignatureState.Invalid))
                v.Evidence.Add(new EvidenceItem(
                    "已签名程序运行于临时/下载类目录",
                    $"路径 {path}",
                    "便携版工具常态",
                    1));
        }

        // ---------- 2. 行为类证据（数据量是证据但不能孤立判断） ----------
        if (s != null && sessionLen > TimeSpan.FromSeconds(60))
        {
            if (s.DownTotal > 0 && s.UpTotal > s.DownTotal * 3 && s.UpTotal > 30_000_000)
                v.Evidence.Add(new EvidenceItem(
                    $"会话内上传({Util.FormatBytes(s.UpTotal)})约为下载({Util.FormatBytes(s.DownTotal)})的 {s.UpTotal / Math.Max(1, s.DownTotal)} 倍",
                    "进程级累计口径，含 TCP 重传；按目的地拆分见「目的地排行」",
                    "网盘同步/备份/直播推流/P2P 均为此形态",
                    2));

            if (sessionLen < TimeSpan.FromSeconds(180) && s.UpTotal > 20_000_000)
            {
                bool wellAnchored = e.Signature == SignatureState.Valid
                    && !string.IsNullOrEmpty(path)
                    && (path!.Contains("\\Program Files", StringComparison.OrdinalIgnoreCase)
                        || path.Contains("\\Windows\\", StringComparison.OrdinalIgnoreCase));
                v.Evidence.Add(new EvidenceItem(
                    $"新出现的进程短时间内上传 {Util.FormatBytes(s.UpTotal)}",
                    $"进程出现约 {sessionLen.TotalSeconds:F0} 秒",
                    wellAnchored ? "已签名且位于常规位置——更新器/云盘常见" : "无法用签名与位置佐证",
                    wellAnchored ? 1 : 2));
            }
        }

        // ---------- 3. 处置层：用户信任优先 ----------
        if (userTrusted)
        {
            v.Status = VerdictStatus.Normal;
            v.Summary = "用户已信任（允许名单生效）——引擎特征仅作记录，不参与定级，可随时在「拦截名单」页撤销";
            v.Evidence.Add(new EvidenceItem(
                $"用户已将此软件加入允许名单（引擎原始特征 {v.Evidence.Count} 项仅作记录）",
                "处置层的用户决定具有最高优先级",
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
            v.Summary = $"多项独立特征组合异常（{v.Evidence.Count} 项证据，其中 {strong} 项强特征）——建议立即核查路径与目的地";
        }
        else if (total >= 2 || mid >= 1)
        {
            v.Status = VerdictStatus.Attention;
            v.Summary = $"存在值得关注的特征（{v.Evidence.Count} 项证据）——请展开证据链并结合目的地判断";
        }
        else if (v.Evidence.Count == 0 && e.Signature == SignatureState.Valid && !inSuspiciousDir)
        {
            v.Status = VerdictStatus.Normal;
            v.Summary = e.SignatureSubject == null ? "未发现可疑点（签名有效）" : $"未发现可疑点（签名有效 · {e.SignatureSubject}）";
        }
        else
        {
            v.Status = VerdictStatus.Unknown;
            v.Summary = "已观察到网络行为，但当前证据不足以判断是否异常——这是诚实的中间结论，建议持续观察其目的地与频率";
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
