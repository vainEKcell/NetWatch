using System.Net;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using NetWatch.Models;

namespace NetWatch.Services;

/// ETW 实时会话：内核网络事件（每进程收发/连接）+ DNS-Client（每进程域名解析）
public sealed class EtwNetworkMonitor : IDisposable
{
    public const string SessionName = "NetWatch-Realtime";

    private TraceEventSession? _session;
    private CancellationTokenSource? _cts;
    private Task? _task;

    public volatile bool Running;
    public volatile string? LastError;
    public long RawEventCount;

    /// 内核网络事件（流量/新连接/断开）
    public event Action<NetEvent>? OnNetEvent;
    /// DNS 解析结果事件
    public event Action<DnsEvent>? OnDnsEvent;

    public void Start()
    {
        _cts = new CancellationTokenSource();
        _task = Task.Run(() => Run(_cts.Token));
    }

    private void Run(CancellationToken ct)
    {
        try
        {
            StopLeftover();
            var session = new TraceEventSession(SessionName);
            _session = session;

            // 顺序关键：必须在首次访问 session.Source 之前启用提供程序，
            // 否则 EnableKernelProvider 抛出“must be enabled first and only once”
            session.EnableKernelProvider(KernelTraceEventParser.Keywords.NetworkTCPIP
                | KernelTraceEventParser.Keywords.Process);
            session.EnableProvider("Microsoft-Windows-DNS-Client");

            var k = session.Source.Kernel;

            // 进程生命周期：Start/DCStart(启动 rundown，覆盖会话开始时已运行的进程)/Stop
            // 3.1.30 中三类事件统一为 ProcessTraceData：ProcessID/ParentID/CommandLine/ImageFileName
            k.ProcessStart   += e => EmitProc(true,  e.TimeStamp, e.ProcessID, e.ParentID, e.ImageFileName, e.CommandLine);
            k.ProcessDCStart += e => EmitProc(true,  e.TimeStamp, e.ProcessID, e.ParentID, e.ImageFileName, e.CommandLine);
            k.ProcessStop    += e => EmitProc(false, e.TimeStamp, e.ProcessID, 0, e.ImageFileName, null);

            k.TcpIpSend          += e => Emit(e.TimeStamp, e.ProcessID, NetProto.Tcp, true,  e.daddr, e.dport, e.size);
            k.TcpIpSendIPV6      += e => Emit(e.TimeStamp, e.ProcessID, NetProto.Tcp, true,  e.daddr, e.dport, e.size);
            k.TcpIpRecv          += e => Emit(e.TimeStamp, e.ProcessID, NetProto.Tcp, false, e.saddr, e.sport, e.size);
            k.TcpIpRecvIPV6      += e => Emit(e.TimeStamp, e.ProcessID, NetProto.Tcp, false, e.saddr, e.sport, e.size);
            k.TcpIpRetransmit    += e => Emit(e.TimeStamp, e.ProcessID, NetProto.Tcp, true,  e.daddr, e.dport, e.size);
            k.TcpIpRetransmitIPV6+= e => Emit(e.TimeStamp, e.ProcessID, NetProto.Tcp, true,  e.daddr, e.dport, e.size);
            k.UdpIpSend          += e => Emit(e.TimeStamp, e.ProcessID, NetProto.Udp, true,  e.daddr, e.dport, e.size);
            k.UdpIpSendIPV6      += e => Emit(e.TimeStamp, e.ProcessID, NetProto.Udp, true,  e.daddr, e.dport, e.size);
            k.UdpIpRecv          += e => Emit(e.TimeStamp, e.ProcessID, NetProto.Udp, false, e.saddr, e.sport, e.size);
            k.UdpIpRecvIPV6      += e => Emit(e.TimeStamp, e.ProcessID, NetProto.Udp, false, e.saddr, e.sport, e.size);
            k.TcpIpConnect       += e => Conn(e.TimeStamp, e.ProcessID, NetProto.Tcp, e.daddr, e.dport);
            k.TcpIpConnectIPV6   += e => Conn(e.TimeStamp, e.ProcessID, NetProto.Tcp, e.daddr, e.dport);
            k.TcpIpDisconnect    += e => Closed(e.TimeStamp, e.ProcessID, NetProto.Tcp, e.daddr, e.dport);
            k.TcpIpDisconnectIPV6+= e => Closed(e.TimeStamp, e.ProcessID, NetProto.Tcp, e.daddr, e.dport);

            // DNS-Client 清单提供程序：3008 = QueryResultsEx（查询结果，含缓存命中）
            session.Source.Dynamic.All += e =>
            {
                try
                {
                    if (e.ProviderName != "Microsoft-Windows-DNS-Client" || (int)e.ID != (int)3008) return;
                    var name = PayloadStr(e, "QueryName", "queryName");
                    if (string.IsNullOrEmpty(name)) return;
                    var results = PayloadStr(e, "QueryResults", "queryResults") ?? "";
                    var ips = ParseIps(results);
                    if (ips.Count == 0) return;
                    Interlocked.Increment(ref RawEventCount);
                    OnDnsEvent?.Invoke(new DnsEvent(e.TimeStamp.ToUniversalTime(), e.ProcessID, name, ips.ToArray()));
                }
                catch { /* 单条解码失败不影响会话 */ }
            };

            Running = true;
            LastError = null;
            Log.Info("ETW 会话已启动（内核网络 + DNS-Client）");
            session.Source.Process();
            Log.Info("ETW 会话已结束");
        }
        catch (Exception ex)
        {
            LastError = ex.Message;
            Log.Error("ETW 会话启动/运行失败", ex);
        }
        finally
        {
            Running = false;
            try { _session?.Stop(); } catch { }
            _session = null;
        }
    }

    /// 内核进程事件（启动/退出，含会话开始时的 rundown）：补父进程与命令行
    public event Action<bool, int, int?, string?, string?, DateTime>? OnProcessEvent;

    private void EmitProc(bool isStart, DateTime t, int pid, int parentPid, string? image, string? cmd)
    {
        try
        {
            OnProcessEvent?.Invoke(isStart, pid, parentPid <= 0 ? null : parentPid,
                string.IsNullOrEmpty(image) ? null : image, cmd, t.ToUniversalTime());
        }
        catch { }
    }

    private void Emit(DateTime t, int pid, NetProto proto, bool send, IPAddress? remote, int remotePort, int bytes)
    {
        try
        {
            Interlocked.Increment(ref RawEventCount);
            OnNetEvent?.Invoke(new NetEvent(
                t.ToUniversalTime(), pid, proto, send,
                remote != null && IPAddress.IsLoopback(remote),
                bytes, remote?.ToString(), remotePort, EventKind.Traffic));
        }
        catch { }
    }

    private void Conn(DateTime t, int pid, NetProto proto, IPAddress? remote, int remotePort)
    {
        try
        {
            Interlocked.Increment(ref RawEventCount);
            OnNetEvent?.Invoke(new NetEvent(t.ToUniversalTime(), pid, proto, true,
                remote != null && IPAddress.IsLoopback(remote), 0, remote?.ToString(), remotePort, EventKind.NewConn));
        }
        catch { }
    }

    private void Closed(DateTime t, int pid, NetProto proto, IPAddress? remote, int remotePort)
    {
        try
        {
            Interlocked.Increment(ref RawEventCount);
            OnNetEvent?.Invoke(new NetEvent(t.ToUniversalTime(), pid, proto, true,
                remote != null && IPAddress.IsLoopback(remote), 0, remote?.ToString(), remotePort, EventKind.Closed));
        }
        catch { }
    }

    private static string? PayloadStr(TraceEvent e, params string[] candidates)
    {
        string[]? names = null;
        try { names = e.PayloadNames; } catch { return null; }
        if (names == null) return null;
        foreach (var c in candidates)
        {
            if (Array.IndexOf(names, c) < 0) continue;
            try { if (e.PayloadByName(c) is string s && s.Length > 0) return s; } catch { }
        }
        return null;
    }

    private static List<string> ParseIps(string results)
    {
        var list = new List<string>();
        foreach (var tok in results.Split(';', ',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (tok.Length == 0) continue;
            if (IPAddress.TryParse(tok, out var ip))
            {
                // ::ffff:a.b.c.d（IPv4-mapped IPv6）归一化为纯 IPv4，与内核事件/连接表的 IP 字符串一致
                list.Add(ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4().ToString() : ip.ToString());
            }
        }
        return list.Distinct().ToList();
    }

    /// 清理上次异常退出遗留的同名会话
    private static void StopLeftover()
    {
        try
        {
            foreach (var name in TraceEventSession.GetActiveSessionNames())
            {
                if (!string.Equals(name, SessionName, StringComparison.OrdinalIgnoreCase)) continue;
                using var s = new TraceEventSession(name);
                s.Stop();
                Log.Info($"已清理遗留 ETW 会话：{name}");
            }
        }
        catch { }
    }

    public void Dispose()
    {
        try { _cts?.Cancel(); } catch { }
        try { _session?.Stop(); } catch { }
        try { _session?.Dispose(); } catch { }
        try { _task?.Wait(2000); } catch { }
    }
}
