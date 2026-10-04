using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text.Json;
using NetWatch.Models;

namespace NetWatch.Services;

public sealed record DohResult(string Domain, string LocalIps, string RefIps, string Verdict, RiskLevel Level);

/// 「DNS 体检」：手动触发的主动交叉验证。
/// 这是本程序唯一的主动联网功能——仅在用户点击按钮时向所选公共 DoH 发起少量查询。
public sealed class DnsCheckService
{
    public static readonly (string Name, string Url)[] Endpoints =
    {
        ("阿里公共 DNS (223.5.5.5)", "https://223.5.5.5/resolve"),
        ("腾讯 DNSPod (doh.pub)", "https://doh.pub/resolve"),
        ("Cloudflare (1.1.1.1)", "https://1.1.1.1/resolve"),
    };

    public static readonly string[] DefaultProbes = { "www.baidu.com", "www.qq.com", "www.microsoft.com" };

    public async Task<List<DohResult>> RunAsync(string[] domains, string endpointUrl, IProgress<string>? progress)
    {
        var results = new List<DohResult>();
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(8) };
        http.DefaultRequestHeaders.TryAddWithoutValidation("accept", "application/dns-json");

        foreach (var raw in domains)
        {
            var domain = raw.Trim();
            if (domain.Length == 0) continue;
            progress?.Report($"正在体检 {domain} …");

            string local;
            try
            {
                var ips = await Dns.GetHostAddressesAsync(domain);
                local = ips.Length == 0 ? "无记录" : string.Join(", ", ips.Select(a => a.ToString()).Distinct());
            }
            catch
            {
                local = "解析失败";
            }

            string reference;
            try
            {
                reference = await QueryDoH(http, endpointUrl, domain);
            }
            catch
            {
                reference = "参考解析失败";
            }

            var (verdict, level) = Judge(domain, local, reference);
            results.Add(new DohResult(domain, local, reference, verdict, level));
        }
        return results;
    }

    private static (string, RiskLevel) Judge(string domain, string local, string reference)
    {
        if (reference == "参考解析失败")
            return ("无法完成比对（所选 DoH 不可达，检查网络或换一个参考源）", RiskLevel.Low);

        if (local == "解析失败")
            return ("⚠ 本机解析失败，但参考源有记录——解析环节可能被破坏", RiskLevel.Medium);

        bool publicDomain = Util.IsPublicDomain(domain);
        var localSet = SplitIps(local);

        if (publicDomain && localSet.Any(ip => Util.IsLanIp(ip) || Util.IsLoopbackIp(ip)))
            return ("❌ 可疑：本机把该公网域名解析到内网/回环地址——疑似被劫持（本地开发环境除外）", RiskLevel.High);

        var refSet = SplitIps(reference);
        if (refSet.Count > 0 && localSet.Overlaps(refSet))
            return ("✅ 与参考解析一致", RiskLevel.None);

        return ("⚠ 与参考解析不一致——公共域名常见 CDN 调度差异，也可能是被劫持，建议换参考源复核", RiskLevel.Medium);
    }

    private static HashSet<IPAddress> SplitIps(string s) =>
        s.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
         .Select(x => IPAddress.TryParse(x, out var a) ? a : null)
         .Where(x => x != null)
         .Select(x => x!)
         .ToHashSet();

    private static async Task<string> QueryDoH(HttpClient http, string endpoint, string domain)
    {
        var url = $"{endpoint}?name={Uri.EscapeDataString(domain)}&type=A";
        using var resp = await http.GetAsync(url);
        resp.EnsureSuccessStatusCode();
        await using var stream = await resp.Content.ReadAsStreamAsync();
        using var doc = await JsonDocument.ParseAsync(stream);

        if (!doc.RootElement.TryGetProperty("Answer", out var answers) || answers.GetArrayLength() == 0)
        {
            int status = doc.RootElement.TryGetProperty("Status", out var st) ? st.GetInt32() : -1;
            return status == 3 ? "NXDOMAIN（域名不存在）" : "无记录";
        }

        var ips = new List<string>();
        foreach (var a in answers.EnumerateArray())
        {
            try
            {
                int type = a.TryGetProperty("type", out var t) ? t.GetInt32() : 1;
                if (type != 1) continue; // 只要 A 记录
                var data = a.GetProperty("data").GetString();
                if (data != null && IPAddress.TryParse(data, out var ip)
                    && ip.AddressFamily == AddressFamily.InterNetwork)
                    ips.Add(data);
            }
            catch { }
        }
        return ips.Count == 0 ? "无记录" : string.Join(", ", ips.Distinct());
    }
}
