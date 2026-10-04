using System.Net;
using System.Windows.Media;
using NetWatch.Models;
using NetWatch.Services;

namespace NetWatch.ViewModels;

public abstract class VmBase : System.ComponentModel.INotifyPropertyChanged
{
    public event System.ComponentModel.PropertyChangedEventHandler? PropertyChanged;
    protected void Raise(string name) => PropertyChanged?.Invoke(this, new(name));
    protected void RaiseAll(params string[] names)
    {
        foreach (var n in names) PropertyChanged?.Invoke(this, new(n));
    }
}

internal static class UiBrushes
{
    private static SolidColorBrush B(byte r, byte g, byte b)
    {
        var sb = new SolidColorBrush(Color.FromRgb(r, g, b));
        sb.Freeze();
        return sb;
    }

    public static readonly SolidColorBrush Green = B(0x4C, 0xC8, 0x78);
    public static readonly SolidColorBrush Blue = B(0x46, 0xA0, 0xFF);
    public static readonly SolidColorBrush Amber = B(0xE3, 0xA8, 0x36);
    public static readonly SolidColorBrush Red = B(0xE5, 0x53, 0x4B);
    public static readonly SolidColorBrush Dim = B(0x8B, 0x95, 0xA7);
    public static readonly SolidColorBrush Faint = B(0x3D, 0x47, 0x59);
    public static readonly SolidColorBrush Fg = B(0xD8, 0xDE, 0xE9);

    public static SolidColorBrush Risk(RiskLevel lv) => lv switch
    {
        RiskLevel.High => Red,
        RiskLevel.Medium => Amber,
        RiskLevel.Low => Dim,
        _ => Faint,
    };
}

public sealed class ProcessRowVM : VmBase
{
    public int Pid { get; private set; }
    public string Name { get; private set; } = "";
    public string Company { get; private set; } = "";
    public string Path { get; private set; } = "";
    public ImageSource? IconSource { get; private set; }
    public string UpSpeedText { get; private set; } = "";
    public string DownSpeedText { get; private set; } = "";
    public string UpTotalText { get; private set; } = "";
    public string DownTotalText { get; private set; } = "";
    public double UpSpeedBytes { get; private set; }
    public double DownSpeedBytes { get; private set; }
    public long UpTotalBytes { get; private set; }
    public long DownTotalBytes { get; private set; }
    public int ConnCount { get; private set; }
    public RiskLevel Risk { get; private set; }
    public byte RiskByte { get; private set; }
    public SolidColorBrush RiskBrush { get; private set; } = UiBrushes.Faint;
    public string RiskText { get; private set; } = "";
    public bool Blocked { get; private set; }

    public void Update(ProcessEntry e, PidStats? s, int conns, Verdict verdict)
    {
        Pid = e.Pid;
        Name = e.Exited ? e.Name + "（已退出）" : e.Name;
        Company = e.Company ?? e.Description ?? "";
        Path = e.Path ?? "";
        IconSource = e.Icon;
        UpSpeedBytes = s?.UpSpeed ?? 0;
        DownSpeedBytes = s?.DownSpeed ?? 0;
        UpTotalBytes = s?.UpTotal ?? 0;
        DownTotalBytes = s?.DownTotal ?? 0;
        UpSpeedText = Util.FormatSpeed(UpSpeedBytes);
        DownSpeedText = Util.FormatSpeed(DownSpeedBytes);
        UpTotalText = Util.FormatBytes(UpTotalBytes);
        DownTotalText = Util.FormatBytes(DownTotalBytes);
        ConnCount = conns;
        Risk = verdict.Status switch
        {
            VerdictStatus.HighRisk => RiskLevel.High,
            VerdictStatus.Attention => RiskLevel.Medium,
            _ => RiskLevel.None,
        };
        RiskByte = verdict.RiskByte;
        RiskBrush = verdict.Status switch
        {
            VerdictStatus.HighRisk => UiBrushes.Red,
            VerdictStatus.Attention => UiBrushes.Amber,
            VerdictStatus.Unknown => UiBrushes.Dim,
            _ => UiBrushes.Faint,
        };
        RiskText = verdict.Summary + (verdict.Evidence.Count == 0
            ? ""
            : "\n" + string.Join("\n", verdict.Evidence.Select(x => $"• {x.Statement}" + (x.Caveat != null ? $"（误报可能：{x.Caveat}）" : ""))));
        Blocked = e.FirewallBlocked;
        RaiseAll(nameof(Pid), nameof(Name), nameof(Company), nameof(Path), nameof(IconSource),
            nameof(UpSpeedText), nameof(DownSpeedText), nameof(UpTotalText), nameof(DownTotalText),
            nameof(UpSpeedBytes), nameof(DownSpeedBytes), nameof(UpTotalBytes), nameof(DownTotalBytes),
            nameof(ConnCount), nameof(Risk), nameof(RiskByte), nameof(RiskBrush), nameof(RiskText), nameof(Blocked));
    }
}

public sealed class EventRowVM : VmBase
{
    public int Pid { get; private set; }
    public DateTime RawTime { get; private set; }
    public string TimeText { get; private set; } = "";
    public string KindText { get; private set; } = "";
    public SolidColorBrush KindBrush { get; private set; } = UiBrushes.Fg;
    public string Process { get; private set; } = "";
    public string Detail { get; private set; } = "";
    public string BytesText { get; private set; } = "";
    public long RawBytes { get; private set; }
    public string RawKind { get; private set; } = "";

    public void UpdateName(string name)
    {
        Process = name;
        Raise(nameof(Process));
    }

    public static EventRowVM FromNet(NetEvent e, string procName, DnsService dns)
    {
        var vm = new EventRowVM
        {
            Pid = e.Pid,
            RawTime = e.TimeUtc.ToLocalTime(),
            TimeText = e.TimeUtc.ToLocalTime().ToString("HH:mm:ss"),
            Process = procName,
            RawBytes = e.Kind == EventKind.Traffic ? e.Bytes : 0,
        };
        string domain = e.RemoteIp != null ? dns.LookupDomain(e.RemoteIp) ?? "" : "";
        string remote = e.RemoteIp == null ? "" : Util.FormatEndpoint(e.RemoteIp, e.RemotePort);
        if (domain.Length > 0) remote += $" ({domain})";
        vm.Detail = remote;
        switch (e.Kind)
        {
            case EventKind.NewConn:
                vm.KindText = "新连接"; vm.KindBrush = UiBrushes.Green; vm.RawKind = "新连接"; break;
            case EventKind.Closed:
                vm.KindText = "断开"; vm.KindBrush = UiBrushes.Dim; vm.RawKind = "断开"; break;
            default:
                if (e.IsSend) { vm.KindText = "大额上传"; vm.KindBrush = UiBrushes.Amber; vm.RawKind = "大额上传"; }
                else { vm.KindText = "大额下载"; vm.KindBrush = UiBrushes.Blue; vm.RawKind = "大额下载"; }
                vm.BytesText = Util.FormatBytes(e.Bytes);
                break;
        }
        vm.RaiseAll(nameof(TimeText), nameof(KindText), nameof(KindBrush), nameof(Process), nameof(Detail), nameof(BytesText));
        return vm;
    }

    public static EventRowVM FromSystem(string text)
    {
        var vm = new EventRowVM
        {
            Pid = -1,
            RawTime = DateTime.Now,
            TimeText = DateTime.Now.ToString("HH:mm:ss"),
            KindText = "系统", KindBrush = UiBrushes.Dim, RawKind = "系统",
            Detail = text,
        };
        vm.RaiseAll(nameof(TimeText), nameof(KindText), nameof(KindBrush), nameof(Process), nameof(Detail));
        return vm;
    }

    public static EventRowVM FromAlert(DateTime time, RiskLevel level, string text)
    {
        var vm = new EventRowVM
        {
            Pid = -1,
            RawTime = time.ToLocalTime(),
            TimeText = time.ToLocalTime().ToString("HH:mm:ss"),
            KindText = "DNS/配置告警",
            KindBrush = level == RiskLevel.High ? UiBrushes.Red : level == RiskLevel.Medium ? UiBrushes.Amber : UiBrushes.Dim,
            RawKind = "DNS/配置告警",
            Detail = text,
        };
        vm.RaiseAll(nameof(TimeText), nameof(KindText), nameof(KindBrush), nameof(Detail));
        return vm;
    }
}

public sealed class ConnRowVM : VmBase
{
    public string Remote { get; private set; } = "";
    public string Local { get; private set; } = "";
    public string ProtoText { get; private set; } = "";
    public string State { get; private set; } = "";
    public string Scope { get; private set; } = "";

    public static ConnRowVM From(ConnectionInfo c, DnsService dns)
    {
        var (raddr, _) = Util.SplitEndpoint(c.Remote);
        var domain = dns.LookupDomain(raddr);
        var vm = new ConnRowVM
        {
            Remote = domain == null ? c.Remote : $"{c.Remote} ({domain})",
            Local = c.Local,
            ProtoText = c.Proto == NetProto.Tcp ? "TCP" : "UDP",
            State = c.State,
            // UDP 表只有本地绑定、没有远端，公网/局域网分类无意义
            Scope = c.Proto == NetProto.Udp ? "-" : Util.ScopeText(c.IsLoopback, c.IsLan),
        };
        vm.RaiseAll(nameof(Remote), nameof(Local), nameof(ProtoText), nameof(State), nameof(Scope));
        return vm;
    }
}

public sealed class DnsRowVM : VmBase
{
    public int Pid { get; private set; }
    public string TimeText { get; private set; } = "";
    public string Process { get; private set; } = "";
    public string Domain { get; private set; } = "";
    public string Ips { get; private set; } = "";
    public bool IsAlert { get; private set; }
    public string AlertText { get; private set; } = "";

    public void UpdateName(string name)
    {
        Process = name;
        Raise(nameof(Process));
    }

    public static DnsRowVM From(DnsStreamItem it, string procName)
    {
        var vm = new DnsRowVM
        {
            Pid = it.Pid,
            TimeText = it.TimeUtc.ToLocalTime().ToString("HH:mm:ss"),
            Process = procName,
            Domain = it.Domain,
            Ips = it.Ips,
            IsAlert = it.Alert,
            AlertText = it.AlertText,
        };
        vm.RaiseAll(nameof(TimeText), nameof(Process), nameof(Domain), nameof(Ips), nameof(IsAlert), nameof(AlertText));
        return vm;
    }
}

public sealed class RemoteRowVM : VmBase
{
    public string Display { get; private set; } = "";
    public string Scope { get; private set; } = "";
    public string UpText { get; private set; } = "";
    public string DownText { get; private set; } = "";
    public long UpBytes { get; private set; }
    public long DownBytes { get; private set; }
    public string ProcessesText { get; private set; } = "";
    public string LastText { get; private set; } = "";

    public void Update(string ip, RemoteStats rs, string? domain, string procNames)
    {
        Display = domain == null ? ip : $"{domain} ({ip})";
        bool loop = IPAddress.TryParse(ip, out var a) && IPAddress.IsLoopback(a);
        bool lan = a != null && !loop && Util.IsLanIp(a);
        Scope = Util.ScopeText(loop, lan);
        UpBytes = rs.Up; DownBytes = rs.Down;
        UpText = Util.FormatBytes(rs.Up);
        DownText = Util.FormatBytes(rs.Down);
        ProcessesText = procNames;
        LastText = rs.LastUtc.ToLocalTime().ToString("HH:mm:ss");
        RaiseAll(nameof(Display), nameof(Scope), nameof(UpText), nameof(DownText),
            nameof(UpBytes), nameof(DownBytes), nameof(ProcessesText), nameof(LastText));
    }
}

public sealed class PortRowVM : VmBase
{
    public string ProtoText { get; private set; } = "";
    public int Port { get; private set; }
    public string Bind { get; private set; } = "";
    public string BindText { get; private set; } = "";
    public int Pid { get; private set; }
    public string Process { get; private set; } = "";

    public void Update(ConnectionInfo c, string procName)
    {
        ProtoText = c.Proto == NetProto.Tcp ? "TCP" : "UDP";
        var (addr, port) = Util.SplitEndpoint(c.Local);
        Port = port;
        Bind = c.Local;
        BindText = addr is "0.0.0.0" or "::" ? "⚠ 对局域网开放" : addr is "127.0.0.1" or "::1" ? "仅本机" : "特定地址";
        Pid = c.Pid;
        Process = procName;
        RaiseAll(nameof(ProtoText), nameof(Port), nameof(Bind), nameof(BindText), nameof(Pid), nameof(Process));
    }
}

public sealed class BlockedAppVM : VmBase
{
    public string DisplayName { get; set; } = "";
    public string Path { get; set; } = "";
    public string RulesText { get; set; } = "";
}

public sealed class ConfigChangeRowVM : VmBase
{
    public string TimeText { get; private set; } = "";
    public string What { get; private set; } = "";
    public string Old { get; private set; } = "";
    public string New { get; private set; } = "";
    public bool Serious { get; private set; }

    public ConfigChangeRowVM(ConfigChange c)
    {
        TimeText = c.TimeUtc.ToLocalTime().ToString("MM-dd HH:mm:ss");
        What = c.What; Old = c.Old; New = c.New; Serious = c.Serious;
        RaiseAll(nameof(TimeText), nameof(What), nameof(Old), nameof(New), nameof(Serious));
    }
}

public sealed class DohResultVM : VmBase
{
    public string Domain { get; }
    public string LocalIps { get; }
    public string RefIps { get; }
    public string Verdict { get; }
    public SolidColorBrush VerdictBrush { get; }

    public DohResultVM(DohResult r)
    {
        Domain = r.Domain; LocalIps = r.LocalIps; RefIps = r.RefIps; Verdict = r.Verdict;
        VerdictBrush = UiBrushes.Risk(r.Level);
    }
}

public sealed class AdapterRowVM : VmBase
{
    public string Name { get; private set; } = "";
    public string Status { get; private set; } = "";
    public string IpsText { get; private set; } = "";
    public string GwText { get; private set; } = "";
    public string DnsText { get; private set; } = "";

    public void Update(AdapterInfo a)
    {
        Name = a.Name;
        Status = a.Status;
        IpsText = a.Ips.Length == 0 ? "—" : string.Join(", ", a.Ips);
        GwText = a.Gateways.Length == 0 ? "—" : string.Join(", ", a.Gateways);
        DnsText = a.Dns.Length == 0 ? "—" : string.Join(", ", a.Dns);
        RaiseAll(nameof(Name), nameof(Status), nameof(IpsText), nameof(GwText), nameof(DnsText));
    }
}
