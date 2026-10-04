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
        => loopback ? "回环" : lan ? "局域网" : "公网";
}
