using System.Net;

namespace NetWatch.Services;

public static class Util
{
    public static string FormatBytes(long b)
    {
        double v = b;
        if (v < 1024) return $"{b} B";
        v /= 1024; if (v < 1024) return $"{v:F1} KB";
        v /= 1024; if (v < 1024) return $"{v:F2} MB";
        v /= 1024; return $"{v:F2} GB";
    }

    public static string FormatSpeed(double bytesPerSec) => FormatBytes((long)bytesPerSec) + "/s";

    public static bool IsLoopbackIp(IPAddress ip) => IPAddress.IsLoopback(ip);

    /// 内网 / 链路本地地址（RFC1918 + 169.254 + IPv6 内网段）
    public static bool IsLanIp(IPAddress ip)
    {
        if (ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal) return true;
        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            var b = ip.GetAddressBytes();
            return b[0] == 10
                || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
                || (b[0] == 192 && b[1] == 168)
                || (b[0] == 169 && b[1] == 254);
        }
        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            var b = ip.GetAddressBytes();
            return (b[0] & 0xFE) == 0xFC; // fc00::/7 ULA
        }
        return false;
    }

    /// 是否“公网域名”——含点、非本地后缀、非纯 IP、非反解域名
    public static bool IsPublicDomain(string domain)
    {
        if (string.IsNullOrEmpty(domain)) return false;
        var d = domain.TrimEnd('.').ToLowerInvariant();
        if (d.Length == 0 || !d.Contains('.')) return false;                 // 单标签主机名
        if (IPAddress.TryParse(d, out _)) return false;                       // 本身就是 IP
        string[] localTlds = { ".local", ".lan", ".home", ".internal", ".corp", ".arpa", ".localhost", ".test", ".invalid" };
        foreach (var t in localTlds)
            if (d.EndsWith(t, StringComparison.Ordinal)) return false;
        return true;
    }

    public static string ScopeText(bool loopback, bool lan)
        => loopback ? L10n.T("scope.loopback") : lan ? L10n.T("scope.lan") : L10n.T("scope.public");

    /// 拆分 "1.2.3.4:443" / "[fe80::1]:1900" 端点表示，IPv6 用方括号约定
    public static (string Addr, int Port) SplitEndpoint(string endpoint)
    {
        if (!string.IsNullOrEmpty(endpoint) && endpoint.StartsWith("["))
        {
            int close = endpoint.IndexOf(']');
            if (close > 0)
            {
                var addr = endpoint[1..close];
                int port = 0;
                if (close + 2 < endpoint.Length && endpoint[close + 1] == ':')
                    int.TryParse(endpoint[(close + 2)..], out port);
                return (addr, port);
            }
        }
        int i = endpoint?.LastIndexOf(':') ?? -1;
        if (i > 0 && int.TryParse(endpoint![(i + 1)..], out var p)) return (endpoint[..i], p);
        return (endpoint ?? "", 0);
    }

    /// 地址+端口 → 显示串；地址含冒号（IPv6）时用方括号，避免歧义
    public static string FormatEndpoint(string addr, int port)
        => string.IsNullOrEmpty(addr) ? "" : addr.Contains(':') ? $"[{addr}]:{port}" : $"{addr}:{port}";
}
