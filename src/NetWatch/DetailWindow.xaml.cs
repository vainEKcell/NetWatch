using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using NetWatch.Models;
using NetWatch.Services;
using NetWatch.ViewModels;

namespace NetWatch;

/// 进程 / 事件的详情与解读小窗：展示证据链 + 通俗的"怎么分析"指南。
/// 内容在代码中构建（数据来自 MainViewModel 的快照），样式走主题画刷。
public partial class DetailWindow : Window
{
    private readonly MainViewModel _vm;

    public DetailWindow(MainViewModel vm, int pid, string? eventNote)
    {
        InitializeComponent();
        _vm = vm;
        Build(pid, eventNote);
    }

    private static SolidColorBrush Res(string key) =>
        Application.Current?.TryFindResource(key) as SolidColorBrush ?? new SolidColorBrush(Colors.Gray);

    private static TextBlock Header(string text) => new()
    {
        Text = text,
        FontSize = 11.5,
        Margin = new Thickness(0, 12, 0, 3),
        Foreground = Res("DimBrush"),
    };

    private static TextBlock Line(string text, Brush? foreground = null, bool wrap = true, bool bold = false)
    {
        var tb = new TextBlock { Text = text, TextWrapping = wrap ? TextWrapping.Wrap : TextWrapping.NoWrap, Margin = new Thickness(0, 1, 0, 1) };
        if (foreground != null) tb.Foreground = foreground;
        if (bold) tb.FontWeight = FontWeights.SemiBold;
        return tb;
    }

    private void Build(int pid, string? eventNote)
    {
        var entry = _vm.Tracker.Get(pid);
        var inst = _vm.Entities.GetProcess(pid);
        var id = _vm.Entities.GetIdentity(inst?.IdentityKey);
        var verdict = _vm.GetVerdictFor(pid);
        var svcs = _vm.Entities.ServicesOf(pid);
        var conns = _vm.ConnectionsOf(pid);
        var dnsList = _vm.Dns.RecentDomains(pid);

        // ---- 头部 ----
        var head = new StackPanel { Orientation = Orientation.Horizontal };
        if (entry.Icon != null)
            head.Children.Add(new Image { Source = entry.Icon, Width = 32, Height = 32, VerticalAlignment = VerticalAlignment.Center });
        var headText = new StackPanel { Margin = new Thickness(10, 0, 0, 0), VerticalAlignment = VerticalAlignment.Center };
        headText.Children.Add(Line($"{entry.Name}  (PID {entry.Pid})", Res("FgBrush"), bold: true));
        headText.Children.Add(Line(entry.Company ?? entry.Description ?? "", Res("DimBrush")));
        head.Children.Add(headText);
        Root.Children.Add(head);

        // ---- 事件上下文（从事件流进入时） ----
        if (!string.IsNullOrEmpty(eventNote))
        {
            Root.Children.Add(Header("这条事件"));
            Root.Children.Add(Line(eventNote, Res("DimBrush")));
            Root.Children.Add(Line(L10n.T("dw.event.explain"), Res("DimBrush")));
        }

        // ---- 判定与证据 ----
        Root.Children.Add(Header(L10n.T("d.verdict")));
        if (verdict == null)
        {
            Root.Children.Add(Line(L10n.T("d.analyzing"), Res("DimBrush")));
        }
        else
        {
            var statusKey = verdict.Status switch
            {
                VerdictStatus.HighRisk => "verdict.highrisk",
                VerdictStatus.Attention => "verdict.attention",
                VerdictStatus.Unknown => "verdict.unknown",
                _ => "verdict.normal",
            };
            Root.Children.Add(Line($"[{L10n.T(statusKey)}] {verdict.Summary}", Res(verdict.Status switch
            {
                VerdictStatus.HighRisk => "RedBrush",
                VerdictStatus.Attention => "AmberBrush",
                VerdictStatus.Unknown => "DimBrush",
                _ => "GreenBrush",
            }), bold: true));
            if (verdict.Evidence.Count == 0)
                Root.Children.Add(Line(L10n.T("d.noEvidence"), Res("DimBrush")));
            foreach (var ev in verdict.Evidence)
            {
                Root.Children.Add(Line($"• {ev.Statement}"));
                if (ev.Basis != null) Root.Children.Add(Line($"    {L10n.T("dw.basis")}：{ev.Basis}", Res("DimBrush")));
                if (ev.Caveat != null) Root.Children.Add(Line($"    {L10n.T("dw.caveat")}：{ev.Caveat}", Res("DimBrush")));
            }
        }

        // ---- 基本信息 ----
        Root.Children.Add(Header(L10n.T("d.path")));
        Root.Children.Add(Line(entry.Path ?? L10n.T("d.pathUnavailable"), Res("DimBrush")));
        Root.Children.Add(Header(L10n.T("d.signature")));
        Root.Children.Add(Line(SignatureText(entry.Signature, entry.SignatureSubject), SignatureBrush(entry.Signature)));
        Root.Children.Add(Header(L10n.T("d.parent")));
        Root.Children.Add(Line(inst?.ParentPid is { } pp
            ? $"PID {pp}" + (_vm.Entities.GetProcess(pp)?.Name is { } pn ? $" · {pn}" : "")
            : L10n.T("d.parentUnknown"), Res("DimBrush")));
        Root.Children.Add(Header(L10n.T("d.cmdline")));
        Root.Children.Add(Line(inst?.CommandLine ?? L10n.T("d.cmdNone"), Res("DimBrush")));
        Root.Children.Add(Header(L10n.T("d.services")));
        Root.Children.Add(Line(svcs.Count == 0 ? L10n.T("d.noServices")
            : string.Join("、", svcs.Select(s => s.DisplayName == s.Name ? s.Name : $"{s.Name} ({s.DisplayName})")), Res("DimBrush")));
        Root.Children.Add(Header(L10n.T("d.identity")));
        Root.Children.Add(Line(id == null ? L10n.T("common.unknown")
            : $"{L10n.T(id.Kind switch { IdentityKind.Signed => "id.signed", IdentityKind.PathOnly => "id.pathOnly", IdentityKind.SystemReserved => "id.sysReserved", IdentityKind.Packaged => "id.packaged", _ => "common.unknown" })} · {id.DisplayName}" +
              (id.Kind != IdentityKind.SystemReserved ? $" · {L10n.T("common.firstSeen", id.FirstSeenUtc.ToLocalTime().ToString("MM-dd HH:mm"))}" : ""),
            Res("DimBrush")));

        // ---- 当前连接 ----
        Root.Children.Add(Header(L10n.T("d.conns")));
        if (conns.Count == 0)
            Root.Children.Add(Line(L10n.T("d.noDns"), Res("DimBrush")));
        foreach (var c in conns.Take(20))
            Root.Children.Add(Line($"  [{c.Proto}] {c.Local} → {c.Remote}（{c.State}，{Util.ScopeText(c.IsLoopback, c.IsLan)}）", Res("DimBrush")));

        // ---- 最近 DNS ----
        Root.Children.Add(Header(L10n.T("d.recentDns")));
        var doms = _vm.Dns.RecentDomains(pid);
        if (doms.Count == 0) Root.Children.Add(Line(L10n.T("d.noDns"), Res("DimBrush")));
        else foreach (var d in doms) Root.Children.Add(Line(d, Res("DimBrush")));

        // ---- 解读指南 ----
        Root.Children.Add(Header(L10n.T("dw.guide.title")));
        foreach (var line in L10n.T("dw.guide").Split('\n'))
            Root.Children.Add(Line(line.TrimEnd('\r'), Res("DimBrush")));
    }

    private static string SignatureText(SignatureState st, string? subject) => st switch
    {
        SignatureState.Valid => subject == null ? L10n.T("sig.valid") : $"{L10n.T("sig.valid")} · {subject}",
        SignatureState.Unsigned => L10n.T("sig.unsigned"),
        SignatureState.Untrusted => $"{L10n.T("sig.untrusted")}{(subject == null ? "" : $" · {subject}")} {L10n.T("sig.untrustedSuffix")}",
        SignatureState.Invalid => L10n.T("sig.invalid"),
        _ => L10n.T("sig.unknown"),
    };

    private static Brush SignatureBrush(SignatureState st) => st switch
    {
        SignatureState.Valid => Res("GreenBrush"),
        SignatureState.Unsigned or SignatureState.Untrusted => Res("AmberBrush"),
        SignatureState.Invalid => Res("RedBrush"),
        _ => Res("DimBrush"),
    };
}
