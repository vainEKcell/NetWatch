using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Xml.Linq;

namespace NetWatch.Services;

public sealed record BlockedConnectionEvent(DateTime TimeUtc, int Pid, string? AppPath, string RemoteIp, int RemotePort, string Protocol);

/// 安全日志 5157（WFP 拦截连接）订阅——补上“这条连接被防火墙拦了”的权威信号。
/// 前提：审核策略“审核筛选平台连接”已启用（设置页一键启用，auditpol 修改可逆）。
public sealed class FirewallAuditWatcher : IDisposable
{
    /// “审核筛选平台连接”子类别的固定 GUID
    public const string SubcategoryGuid = "{0CCE9226-69AE-11D9-BED3-505054503030}";

    private EventLogWatcher? _watcher;

    public static (bool Success, bool Failure) QueryAuditState()
    {
        var (ok, output) = RunAuditpol($"/get /subcategory:{SubcategoryGuid}");
        if (!ok) return (false, false);
        bool success = output.Contains("成功") || output.Contains("Success", StringComparison.OrdinalIgnoreCase);
        bool failure = output.Contains("失败") || output.Contains("Failure", StringComparison.OrdinalIgnoreCase);
        return (success, failure);
    }

    public static bool EnableAudit() =>
        RunAuditpol($"/set /subcategory:{SubcategoryGuid} /success:enable /failure:enable").Item1;

    public static bool DisableAudit() =>
        RunAuditpol($"/set /subcategory:{SubcategoryGuid} /success:disable /failure:disable").Item1;

    private static (bool Ok, string Output) RunAuditpol(string args)
    {
        try
        {
            var psi = new ProcessStartInfo("auditpol.exe", args)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
            };
            using var p = Process.Start(psi)!;
            string output = p.StandardOutput.ReadToEnd();
            p.WaitForExit(5000);
            return (p.ExitCode == 0, output);
        }
        catch (Exception ex) { Log.Error("auditpol 执行失败", ex); return (false, ""); }
    }

    /// 订阅安全日志 5157。返回是否成功启动（未启用审计策略时事件不会到达，但订阅本身可先建立）。
    public bool Start(Action<BlockedConnectionEvent> onBlocked)
    {
        try
        {
            var query = new EventLogQuery("Security", PathType.LogName, "*[System[(EventID=5157)]]");
            _watcher = new EventLogWatcher(query);
            _watcher.EventRecordWritten += (_, args) =>
            {
                try
                {
                    var e = args.EventRecord;
                    var x = XDocument.Parse(e.ToXml());
                    string P(string name) =>
                        x.Descendants("Data").FirstOrDefault(d => (string?)d.Attribute("Name") == name)?.Value ?? "";
                    int pid = (int?)(x.Descendants("Execution").FirstOrDefault()?.Attribute("ProcessID")) ?? 0;
                    int protoId = int.TryParse(P("Protocol"), out var pn) ? pn : 0;
                    string proto = protoId switch { 6 => "TCP", 17 => "UDP", 1 => "ICMP", _ => $"IP({protoId})" };
                    onBlocked(new BlockedConnectionEvent(
                        e.TimeCreated?.ToUniversalTime() ?? DateTime.UtcNow,
                        pid, string.IsNullOrEmpty(P("Application")) ? null : P("Application"),
                        P("Dest Address"), int.TryParse(P("Dest Port"), out var dp) ? dp : 0, proto));
                }
                catch { /* 单条解析失败不影响订阅 */ }
            };
            _watcher.Enabled = true;
            Log.Info("防火墙拦截审计（5157）订阅已建立");
            return true;
        }
        catch (Exception ex)
        {
            Log.Error("5157 订阅失败（需要管理员权限）", ex);
            return false;
        }
    }

    public void Dispose() { try { _watcher?.Dispose(); } catch { } }
}

/// Sysmon 探测式集成（P4 报告的落地）：机器装了 Sysmon 就富化“运行用户”，没装静默降级。
public sealed class SysmonWatcher : IDisposable
{
    private EventLogWatcher? _watcher;
    public bool Available { get; private set; }

    public static bool IsChannelPresent()
    {
        try
        {
            return EventLogSession.GlobalSession.GetLogNames().Any(n =>
                n.Equals("Microsoft-Windows-Sysmon/Operational", StringComparison.OrdinalIgnoreCase));
        }
        catch { return false; }
    }

    /// 订阅 Sysmon 事件 3（网络连接），回调 (pid, user)
    public bool Start(Action<int, string> onUser)
    {
        try
        {
            var query = new EventLogQuery("Microsoft-Windows-Sysmon/Operational", PathType.LogName,
                "*[System[(EventID=3)]]");
            _watcher = new EventLogWatcher(query);
            _watcher.EventRecordWritten += (_, args) =>
            {
                try
                {
                    var x = XDocument.Parse(args.EventRecord.ToXml());
                    string P(string name) =>
                        x.Descendants("Data").FirstOrDefault(d => (string?)d.Attribute("Name") == name)?.Value ?? "";
                    int pid = int.TryParse(P("ProcessId"), out var p) ? p : 0;
                    var user = P("User");
                    if (pid > 0 && !string.IsNullOrEmpty(user)) onUser(pid, user);
                }
                catch { }
            };
            _watcher.Enabled = true;
            Available = true;
            Log.Info("Sysmon 已检测到，运行用户富化已启用");
            return true;
        }
        catch (Exception ex)
        {
            Log.Info($"Sysmon 不可用（{ex.Message}），用户名富化降级");
            return false;
        }
    }

    public void Dispose() { try { _watcher?.Dispose(); } catch { } }
}
