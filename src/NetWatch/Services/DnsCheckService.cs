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
    public static readonly (string NameKey, string Url)[] Endpoints =
    {
        ("dns.ali", "https://223.5.5.5/resolve"),
        ("dns.dnspod", "https://doh.pub/resolve"),
        ("dns.cloudflare", "https://1.1.1.1/resolve"),
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
            progress?.Report(L10n.T("doh.checking", domain));

            string local;
            try
            {
                var ips = await Dns.GetHostAddressesAsync(domain);
                local = ips.Length == 0 ? L10n.T("doh.noRecord") : string.Join(", ", ips.Select(a => a.ToString()).Distinct());
            }
            catch
            {
                local = L10n.T("doh.localFail");
            }

            string reference;
            try
            {
                reference = await QueryDoH(http, endpointUrl, domain);
            }
            catch
            {
                reference = L10n.T("doh.refFail");
            }

            var (verdict, level) = Judge(domain, local, reference);
            results.Add(new DohResult(domain, local, reference, verdict, level));
        }
        return results;
    }

    private static (string, RiskLevel) Judge(string domain, string local, string reference)
    {
        if (reference == L10n.T("doh.refFail"))
            return (L10n.T("doh.cannotCompare"), RiskLevel.Low);

        if (local == L10n.T("doh.localFail"))
            return (L10n.T("doh.localFailAlert"), RiskLevel.Medium);

        bool publicDomain = Util.IsPublicDomain(domain);
        var localSet = SplitIps(local);

        if (publicDomain && localSet.Any(ip => Util.IsLanIp(ip) || Util.IsLoopbackIp(ip)))
            return (L10n.T("doh.privateIp"), RiskLevel.High);

        var refSet = SplitIps(reference);
        if (refSet.Count > 0 && localSet.Overlaps(refSet))
            return (L10n.T("doh.ok"), RiskLevel.None);

        return (L10n.T("doh.mismatch"), RiskLevel.Medium);
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
            return status == 3 ? L10n.T("doh.nxdomain") : L10n.T("doh.noRecord");
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
        return ips.Count == 0 ? L10n.T("doh.noRecord") : string.Join(", ", ips.Distinct());
    }
}
