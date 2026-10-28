using System.Net;
using System.Net.Sockets;
using NetWatch.Models;

namespace NetWatch.Services;

public sealed record StunAttempt(string Server, IPAddress MappedIp, int MappedPort);

public sealed record NatResult(string Classification, string ExternalIp, IReadOnlyList<StunAttempt> Attempts, string Note);

/// STUN 最小客户端（RFC 5389 Binding Request）+ 实用 NAT 分类。
/// 分类方法：同一个本地 socket 向两个不同 STUN 服务器发探测，
/// 外部端口保持一致 → 锥形（联机友好）；不一致 → 对称（P2P 受限）。
/// 全锥/端口受限锥无法在不支持 RFC 5780 的服务器上严格区分，如实标注。
public static class StunClient
{
    private static readonly (string Host, int Port)[] Servers =
    {
        ("stun.qq.com", 3478),
        ("stun.miwifi.com", 3478),
        ("stun.cloudflare.com", 3478),
    };

    public static async Task<NatResult> DetectAsync(CancellationToken ct)
    {
        var attempts = new List<StunAttempt>();
        IPAddress? extIp = null;
        int extPort = 0;

        using var udp = new UdpClient(AddressFamily.InterNetwork);
        udp.Client.ReceiveTimeout = 4000;

        foreach (var (host, port) in Servers)
        {
            ct.ThrowIfCancellationRequested();
            var r = await SendBindingProbe(udp, host, port, ct);
            if (r == null) continue;
            attempts.Add(new StunAttempt($"{host}:{port}", r.Value.Ip, r.Value.Port));
            if (extIp == null) { extIp = r.Value.Ip; extPort = r.Value.Port; }
            if (attempts.Count >= 2) break;
        }

        if (attempts.Count == 0)
            return new NatResult(L10n.T("ncv.nat.fail"), "", attempts, "");

        var localIp = udp.Client.LocalEndPoint != null
            ? ((IPEndPoint)udp.Client.LocalEndPoint).Address
            : IPAddress.None;

        if (localIp.Equals(extIp))
            return new NatResult(L10n.T("ncv.nat.direct"), extIp.ToString() ?? "", attempts, "");

        if (attempts.Count >= 2)
        {
            if (extPort == attempts[1].MappedPort)
                return new NatResult(L10n.T("ncv.nat.cone"), extIp.ToString() ?? "", attempts, "");
            return new NatResult(L10n.T("ncv.nat.symmetric"), extIp.ToString() ?? "", attempts, "");
        }

        return new NatResult(L10n.T("ncv.nat.insufficient"), extIp.ToString() ?? "", attempts, "");
    }

    private static async Task<(IPAddress Ip, int Port)?> SendBindingProbe(UdpClient udp, string host, int port, CancellationToken ct)
    {
        try
        {
            var addrs = await Dns.GetHostAddressesAsync(host, ct);
            var server = addrs.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
            if (server == null) return null;

            var tx = new byte[12];
            Random.Shared.NextBytes(tx);

            var msg = new byte[20];
            msg[0] = 0x00; msg[1] = 0x01;              // Binding Request
            msg[2] = 0x00; msg[3] = 0x00;              // message length
            msg[4] = 0x21; msg[5] = 0x12; msg[6] = 0xA4; msg[7] = 0x42; // magic cookie
            tx.CopyTo(msg, 8);

            await udp.SendAsync(msg, msg.Length, new IPEndPoint(server, port));

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(4000);
            while (true)
            {
                var res = await udp.ReceiveAsync(timeout.Token);
                var buf = res.Buffer;
                if (buf.Length < 20) continue;
                if (buf[0] != 0x01 || buf[1] != 0x01) continue;              // Binding Success Response (0x0101)
                if (!tx.AsSpan().SequenceEqual(buf.AsSpan(8, 12))) continue; // transaction id
                var mapped = ParseMappedAddress(buf);
                if (mapped != null) return mapped;
            }
        }
        catch (OperationCanceledException) { return null; }
        catch { return null; }
    }

    /// 解析 XOR-MAPPED-ADDRESS（0x0020），退回 MAPPED-ADDRESS（0x0001）
    private static (IPAddress Ip, int Port)? ParseMappedAddress(byte[] buf)
    {
        int len = (buf[2] << 8) | buf[3];
        int pos = 20;
        int end = Math.Min(20 + len, buf.Length);
        (IPAddress, int)? fallback = null;

        while (pos + 4 <= end)
        {
            int type = (buf[pos] << 8) | buf[pos + 1];
            int alen = (buf[pos + 2] << 8) | buf[pos + 3];
            if (alen < 0 || pos + 4 + alen > buf.Length) break;

            if (type == 0x0020 && alen >= 8) // XOR-MAPPED-ADDRESS
            {
                int p = pos + 4;
                int mappedPort = (((buf[p + 2] << 8) | buf[p + 3]) ^ 0x2112) & 0xFFFF;
                var addr = new byte[4];
                var magic = new byte[] { 0x21, 0x12, 0xA4, 0x42 };
                for (int i = 0; i < 4; i++) addr[i] = (byte)(buf[p + 4 + i] ^ magic[i]);
                return (new IPAddress(addr), mappedPort);
            }
            if (type == 0x0001 && alen >= 8 && fallback == null) // MAPPED-ADDRESS
            {
                int p = pos + 4;
                int plainPort = ((buf[p + 2] & 0xFF) << 8) | (buf[p + 3] & 0xFF);
                var addr = new byte[4];
                Array.Copy(buf, p + 4, addr, 0, 4);
                fallback = (new IPAddress(addr), plainPort);
            }
            pos += 4 + ((alen + 3) & ~3);
        }
        return fallback;
    }
}
