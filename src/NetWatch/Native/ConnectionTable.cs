using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using NetWatch.Models;
using NetWatch.Services;

namespace NetWatch.Native;

/// iphlpapi TCP/UDP 连接表快照（IPv4 + IPv6）
public static class ConnectionTable
{
    private static readonly string[] TcpStates =
    {
        "CLOSED", "LISTEN", "SYN_SENT", "SYN_RCVD", "ESTABLISHED", "FIN_WAIT1",
        "FIN_WAIT2", "CLOSE_WAIT", "CLOSING", "LAST_ACK", "TIME_WAIT", "DELETE_TCB"
    };

    /// 拉一次全量快照。失败返回空表。
    public static List<ConnectionInfo> Snapshot()
    {
        var list = new List<ConnectionInfo>(512);
        AppendTcp(list, NativeMethods.AF_INET);
        AppendTcp(list, NativeMethods.AF_INET6);
        AppendUdp(list, NativeMethods.AF_INET);
        AppendUdp(list, NativeMethods.AF_INET6);
        return list;
    }

    private static void AppendTcp(List<ConnectionInfo> list, uint af)
    {
        int size = 0;
        uint rc = NativeMethods.GetExtendedTcpTable(IntPtr.Zero, ref size, false, af, NativeMethods.TCP_TABLE_OWNER_PID_ALL, 0);
        if (rc != 122 || size <= 0) return; // ERROR_INSUFFICIENT_BUFFER

        IntPtr buf = Marshal.AllocHGlobal(size);
        try
        {
            rc = NativeMethods.GetExtendedTcpTable(buf, ref size, false, af, NativeMethods.TCP_TABLE_OWNER_PID_ALL, 0);
            if (rc != 0) return;
            int n = Marshal.ReadInt32(buf, 0);

            if (af == NativeMethods.AF_INET)
            {
                for (int i = 0; i < n; i++)
                {
                    int off = 4 + i * 24;
                    uint state = (uint)Marshal.ReadInt32(buf, off);
                    uint la = (uint)Marshal.ReadInt32(buf, off + 4);
                    uint lp = (uint)Marshal.ReadInt32(buf, off + 8);
                    uint ra = (uint)Marshal.ReadInt32(buf, off + 12);
                    uint rp = (uint)Marshal.ReadInt32(buf, off + 16);
                    int pid = Marshal.ReadInt32(buf, off + 20);

                    var lip = Ip4(la); var rip = Ip4(ra);
                    string remote = state == 2 /*LISTEN*/ ? "*" : $"{rip}:{Swap(rp)}";
                    bool loop = IsLoopback(lip) || IsLoopback(rip);
                    bool lan = !loop && !rip.Equals(IPAddress.Any) && Util.IsLanIp(rip);
                    list.Add(new ConnectionInfo(NetProto.Tcp, $"{lip}:{Swap(lp)}", remote,
                        TcpState(state), pid, loop, lan));
                }
            }
            else
            {
                for (int i = 0; i < n; i++)
                {
                    int off = 4 + i * 56;
                    var la = Ip6(buf, off);
                    uint lp = (uint)Marshal.ReadInt32(buf, off + 20);
                    var ra = Ip6(buf, off + 24);
                    uint rp = (uint)Marshal.ReadInt32(buf, off + 44);
                    uint state = (uint)Marshal.ReadInt32(buf, off + 48);
                    int pid = Marshal.ReadInt32(buf, off + 52);

                    string remote = state == 2 ? "*" : $"{ra}:{Swap(rp)}";
                    bool loop = IsLoopback(la) || IsLoopback(ra);
                    bool lan = !loop && Util.IsLanIp(ra);
                    list.Add(new ConnectionInfo(NetProto.Tcp, $"{la}:{Swap(lp)}", remote,
                        TcpState(state), pid, loop, lan));
                }
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    private static void AppendUdp(List<ConnectionInfo> list, uint af)
    {
        int size = 0;
        uint rc = NativeMethods.GetExtendedUdpTable(IntPtr.Zero, ref size, false, af, NativeMethods.UDP_TABLE_OWNER_PID, 0);
        if (rc != 122 || size <= 0) return;

        IntPtr buf = Marshal.AllocHGlobal(size);
        try
        {
            rc = NativeMethods.GetExtendedUdpTable(buf, ref size, false, af, NativeMethods.UDP_TABLE_OWNER_PID, 0);
            if (rc != 0) return;
            int n = Marshal.ReadInt32(buf, 0);

            if (af == NativeMethods.AF_INET)
            {
                for (int i = 0; i < n; i++)
                {
                    int off = 4 + i * 12;
                    uint la = (uint)Marshal.ReadInt32(buf, off);
                    uint lp = (uint)Marshal.ReadInt32(buf, off + 4);
                    int pid = Marshal.ReadInt32(buf, off + 8);
                    var lip = Ip4(la);
                    list.Add(new ConnectionInfo(NetProto.Udp, $"{lip}:{Swap(lp)}", "-",
                        "无连接", pid, IsLoopback(lip), false));
                }
            }
            else
            {
                for (int i = 0; i < n; i++)
                {
                    int off = 4 + i * 28;
                    var la = Ip6(buf, off);
                    uint lp = (uint)Marshal.ReadInt32(buf, off + 20);
                    int pid = Marshal.ReadInt32(buf, off + 24);
                    list.Add(new ConnectionInfo(NetProto.Udp, $"{la}:{Swap(lp)}", "-",
                        "无连接", pid, IsLoopback(la), false));
                }
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    private static string TcpState(uint s) =>
        s >= 1 && s <= 12 ? TcpStates[s - 1] : $"状态{s}";

    private static IPAddress Ip4(uint networkOrder) =>
        new(BitConverter.GetBytes(networkOrder)); // 内存序 = 网络字节序

    private static IPAddress Ip6(IntPtr buf, int off)
    {
        var b = new byte[16];
        Marshal.Copy(buf + off, b, 0, 16);
        return new IPAddress(b);
    }

    private static bool IsLoopback(IPAddress ip) => IPAddress.IsLoopback(ip);

    /// 端口 DWORD 为网络字节序，取低 16 位交换
    private static int Swap(uint p) => (int)(((p & 0xFF) << 8) | ((p >> 8) & 0xFF));
}
