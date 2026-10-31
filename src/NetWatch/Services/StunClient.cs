using System.Net;
using System.Net.Sockets;
using NetWatch.Models;

namespace NetWatch.Services;

public sealed record StunAttempt(string Server, IPAddress MappedIp, int MappedPort);

public sealed record NatResult(string Classification, string Kind, string ExternalIp, IReadOnlyList<StunAttempt> Attempts, string Note);

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
        ("stun.syncthing.net", 3478),   // 声明 OTHER-ADDRESS（RFC 5780），用于过滤行为测试
        ("stun.cloudflare.com", 3478),
    };

    public static async Task<NatResult> DetectAsync(CancellationToken ct)
    {
        var attempts = new List<StunAttempt>();
        IPAddress? extIp = null;
        int extPort = 0;
        (IPAddress Ip, int Port)? other = null;
        (IPAddress Ip, int Port) otherServer = default;

        using var udp = new UdpClient(AddressFamily.InterNetwork);
        udp.Client.ReceiveTimeout = 4000;

        // 遍历服务器池：取前两个映射判定端口行为；同时寻找声明 OTHER-ADDRESS 的服务器（RFC 5780）
        foreach (var (host, port) in Servers)
        {
            ct.ThrowIfCancellationRequested();
            var addrs = await Dns.GetHostAddressesAsync(host, ct);
            var server = addrs.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
            if (server == null) continue;

            var r = await SendBindingProbe(udp, server, port, ct);
            if (r == null) continue;
            attempts.Add(new StunAttempt($"{host}:{port}", r.Value.Mapped.Ip, r.Value.Mapped.Port));
            if (extIp == null) { extIp = r.Value.Mapped.Ip; extPort = r.Value.Mapped.Port; }
            if (r.Value.Other != null && other == null)
            {
                other = r.Value.Other;
                otherServer = (server, port);
            }
        }

        if (attempts.Count == 0)
            return new NatResult(L10n.T("ncv.nat.fail"), "fail", "", attempts, "");

        var localIp = udp.Client.LocalEndPoint != null
            ? ((IPEndPoint)udp.Client.LocalEndPoint).Address
            : IPAddress.None;

        if (localIp.Equals(extIp))
            return new NatResult(L10n.T("ncv.nat.direct"), "direct", extIp.ToString() ?? "", attempts, L10n.T("ncv.nat.direct.note"));

        if (attempts.Count >= 2)
        {
            if (extPort != attempts[1].MappedPort)
                return new NatResult(L10n.T("ncv.nat.symmetric"), "symmetric", extIp.ToString() ?? "", attempts, "");

            // 端口映射与目标无关（EIM）。过滤行为需 RFC 5780 CHANGE-REQUEST 测试：
            // 服务器须声明 OTHER-ADDRESS 并支持从备用地址回包；找不到此类服务器则如实归入 A/B。
            if (other != null)
            {
                var filtering = await ProbeFilteringAsync(udp, otherServer, other.Value, ct);
                return filtering switch
                {
                    "A" => new NatResult(L10n.T("ncv.nat.fullcone"), "cone", extIp.ToString() ?? "", attempts, L10n.T("ncv.nat.a.note")),
                    "B" => new NatResult(L10n.T("ncv.nat.restrictedcone"), "cone", extIp.ToString() ?? "", attempts, L10n.T("ncv.nat.b.note")),
                    "C" => new NatResult(L10n.T("ncv.nat.portrestricted"), "cone", extIp.ToString() ?? "", attempts, L10n.T("ncv.nat.c.note")),
                    _ => new NatResult(L10n.T("ncv.nat.cone"), "cone", extIp.ToString() ?? "", attempts, L10n.T("ncv.nat.cone.note")),
                };
            }
            return new NatResult(L10n.T("ncv.nat.cone"), "cone", extIp.ToString() ?? "", attempts, L10n.T("ncv.nat.cone.note"));
        }

        return new NatResult(L10n.T("ncv.nat.insufficient"), "insufficient", extIp.ToString() ?? "", attempts, "");
    }

    /// RFC 5780 过滤行为测试。changeFlags：0x06 = 要求服务器换 IP+端口回包；0x02 = 仅换端口。
    /// 收到来自备用地址的响应 → 过滤更宽松。返回 "A"/"B"/"C"，服务器不支持返回 ""。
    private static async Task<string> ProbeFilteringAsync(UdpClient udp, (IPAddress Ip, int Port) server, (IPAddress, int) other, CancellationToken ct)
    {
        // Test 1：CHANGE-REQUEST 同时换 IP 和端口；收到响应 = Endpoint-Independent Filtering（NAT A）
        if (await SendChangeRequest(udp, server.Ip, server.Port, 0x06, ct)) return "A";
        // Test 2：仅换端口；收到 = Address-Dependent Filtering（NAT B）；都收不到 = Address- and Port-Dependent（NAT C）
        if (await SendChangeRequest(udp, server.Ip, server.Port, 0x02, ct)) return "B";
        return "C";
    }

    /// 发送带 CHANGE-REQUEST 属性的 Binding Request，等待来自 OTHER 地址的响应
    private static async Task<bool> SendChangeRequest(UdpClient udp, IPAddress serverIp, int port, byte changeFlags, CancellationToken ct)
    {
        try
        {
            var tx = new byte[12];
            Random.Shared.NextBytes(tx);

            var msg = new byte[28];
            msg[0] = 0x00; msg[1] = 0x01;              // Binding Request
            msg[2] = 0x00; msg[3] = 0x08;              // attributes length = 8
            msg[4] = 0x21; msg[5] = 0x12; msg[6] = 0xA4; msg[7] = 0x42;
            tx.CopyTo(msg, 8);
            // CHANGE-REQUEST (0x0003), length 4, flags（RFC 3489：0x04 换 IP，0x02 换端口）
            msg[20] = 0x00; msg[21] = 0x03; msg[22] = 0x00; msg[23] = 0x04;
            msg[24] = 0; msg[25] = 0; msg[26] = 0; msg[27] = changeFlags;

            await udp.SendAsync(msg, msg.Length, new IPEndPoint(serverIp, port));

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(3000);
            while (true)
            {
                var res = await udp.ReceiveAsync(timeout.Token);
                var buf = res.Buffer;
                if (buf.Length < 20) continue;
                if (buf[0] != 0x01 || buf[1] != 0x01) continue;
                if (!tx.AsSpan().SequenceEqual(buf.AsSpan(8, 12))) continue;
                // 响应来自备用地址（IP 或端口不同）→ 过滤行为放宽，测试成立
                var remote = (IPEndPoint)res.RemoteEndPoint;
                if (!remote.Address.Equals(serverIp) || remote.Port != port)
                    return true;
                // 来自主地址的响应：服务器不支持 CHANGE-REQUEST，视为不支持
                return false;
            }
        }
        catch { return false; }
    }

    private static async Task<((IPAddress Ip, int Port) Mapped, (IPAddress, int)? Other)?> SendBindingProbe(UdpClient udp, IPAddress server, int port, CancellationToken ct)
    {
        try
        {
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
                var parsed = ParseBindingResponse(buf);
                if (parsed.Mapped == null) continue;
                return (parsed.Mapped.Value, parsed.Other);
            }
        }
        catch (OperationCanceledException) { return null; }
        catch { return null; }
    }

    /// 解析 Binding Success Response：XOR-MAPPED-ADDRESS（0x0020，退回 MAPPED-ADDRESS 0x0001）
    /// 与 OTHER-ADDRESS（0x802C，退回 CHANGED-ADDRESS 0x0005，RFC 5780 备用地址）
    private static ((IPAddress, int)? Mapped, (IPAddress, int)? Other) ParseBindingResponse(byte[] buf)
    {
        int len = (buf[2] << 8) | buf[3];
        int pos = 20;
        int end = Math.Min(20 + len, buf.Length);
        (IPAddress, int)? mapped = null, fallback = null, other = null, otherFallback = null;

        while (pos + 4 <= end)
        {
            int type = (buf[pos] << 8) | buf[pos + 1];
            int alen = (buf[pos + 2] << 8) | buf[pos + 3];
            if (alen < 0 || pos + 4 + alen > buf.Length) break;

            if (alen >= 8)
            {
                int p = pos + 4;
                switch (type)
                {
                    case 0x0020: // XOR-MAPPED-ADDRESS
                    {
                        int xPort = (((buf[p + 2] << 8) | buf[p + 3]) ^ 0x2112) & 0xFFFF;
                        var addr = new byte[4];
                        var magic = new byte[] { 0x21, 0x12, 0xA4, 0x42 };
                        for (int i = 0; i < 4; i++) addr[i] = (byte)(buf[p + 4 + i] ^ magic[i]);
                        mapped = (new IPAddress(addr), xPort);
                        break;
                    }
                    case 0x0001 when mapped == null: // MAPPED-ADDRESS
                    {
                        int plainPort = ((buf[p + 2] & 0xFF) << 8) | (buf[p + 3] & 0xFF);
                        var addr = new byte[4];
                        Array.Copy(buf, p + 4, addr, 0, 4);
                        fallback = (new IPAddress(addr), plainPort);
                        break;
                    }
                    case 0x802c: // OTHER-ADDRESS（RFC 5780，明文）
                    {
                        int plainPort = ((buf[p + 2] & 0xFF) << 8) | (buf[p + 3] & 0xFF);
                        var addr = new byte[4];
                        Array.Copy(buf, p + 4, addr, 0, 4);
                        other = (new IPAddress(addr), plainPort);
                        break;
                    }
                    case 0x0005 when other == null: // CHANGED-ADDRESS（RFC 3489 兼容）
                    {
                        int plainPort = ((buf[p + 2] & 0xFF) << 8) | (buf[p + 3] & 0xFF);
                        var addr = new byte[4];
                        Array.Copy(buf, p + 4, addr, 0, 4);
                        otherFallback = (new IPAddress(addr), plainPort);
                        break;
                    }
                }
            }
            pos += 4 + ((alen + 3) & ~3);
        }
        return (mapped ?? fallback, other ?? otherFallback);
    }
}
