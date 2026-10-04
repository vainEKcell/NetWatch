using System.Net;
using System.Windows.Media;

namespace NetWatch.Models;

public enum NetProto : byte { Tcp, Udp }

public enum EventKind : byte { Traffic, NewConn, Closed, System, DnsAlert, ConfigChange }

public enum SignatureState : byte
{
    Unknown,    // 未检测 / 路径未知
    Unsigned,   // 无数字签名
    Valid,      // 签名有效
    Untrusted,  // 签名证书不受信任（自签名等）
    Invalid,    // 签名无效（文件可能被篡改 / 已吊销 / 已过期）
}

public enum RiskLevel : byte { None, Low, Medium, High }

/// ETW 每个收发/连接事件的最小表示（ETW 线程产生，UI 线程消费）
public readonly record struct NetEvent(
    DateTime TimeUtc,
    int Pid,
    NetProto Proto,
    bool IsSend,        // true = 本机发出（上传）
    bool IsLoopback,    // 回环流量（127.x / ::1）
    long Bytes,
    string? RemoteIp,   // 连接类事件才有意义
    int RemotePort,
    EventKind Kind);

/// DNS-Client ETW：一次解析结果
public sealed record DnsEvent(DateTime TimeUtc, int Pid, string Domain, string[] Ips);

/// 网络配置变更（DNS/代理/hosts/WinHTTP）
public sealed record ConfigChange(DateTime TimeUtc, string What, string Old, string New, bool Serious);

/// 一次 TCP/UDP 连接表快照中的一行
public sealed record ConnectionInfo(
    NetProto Proto,
    string Local,
    string Remote,
    string State,
    int Pid,
    bool IsLoopback,
    bool IsLan);

/// 一个进程实例的全部元信息（按 PID 缓存，后台线程解析填充）
public sealed class ProcessEntry
{
    public int Pid { get; init; }
    public string Name { get; set; } = "…";
    public string? Path { get; set; }
    public string? Company { get; set; }
    public string? Description { get; set; }
    public string? ProductName { get; set; }
    public DateTime? StartTimeUtc { get; set; }
    public bool Exited { get; set; }
    public SignatureState Signature { get; set; } = SignatureState.Unknown;
    public string? SignatureSubject { get; set; }
    public ImageSource? Icon { get; set; }
    public RiskLevel Risk { get; set; }
    public List<string> RiskReasons { get; } = new();
    public bool FirewallBlocked { get; set; }
    public DateTime FirstSeenUtc { get; init; } = DateTime.UtcNow;
    public DateTime LastActivityUtc { get; set; } = DateTime.UtcNow;
}
