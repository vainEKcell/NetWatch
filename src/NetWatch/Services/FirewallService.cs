namespace NetWatch.Services;

public sealed record BlockedRule(string Name, string AppPath);

/// Windows 防火墙按程序路径拦截（HNetCfg.FwPolicy2 COM），规则带统一前缀便于管理
public sealed class FirewallService
{
    public const string Prefix = "NetWatch Block";
    private dynamic? _policy;

    public bool Available { get; private set; } = true;
    public string? LastError { get; private set; }

    private void Ensure()
    {
        if (_policy != null) return;
        _policy = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2")
            ?? throw new InvalidOperationException("找不到防火墙 COM 组件"));
        Available = true;
    }

    public void BlockApp(string path, string displayName)
    {
        Ensure();
        AddRule($"{Prefix} · {displayName} · 出站", path, 2);
        AddRule($"{Prefix} · {displayName} · 入站", path, 1);
        Log.Info($"已创建防火墙拦截：{path}");
    }

    private void AddRule(string name, string path, int direction)
    {
        if (RuleExists(name)) return;
        dynamic rule = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule")
            ?? throw new InvalidOperationException("找不到防火墙规则 COM 组件"));
        rule.Name = name;
        rule.Description = "由流量哨兵 NetWatch 创建，可在本程序「拦截名单」或 Windows 防火墙中移除";
        rule.ApplicationName = path;
        rule.Action = 0;            // NET_FW_ACTION_BLOCK
        rule.Direction = direction; // 1 = 入站, 2 = 出站
        rule.Enabled = true;
        rule.Profiles = int.MaxValue; // 所有配置文件
        _policy.Rules.Add(rule);
    }

    public List<BlockedRule> ListRules()
    {
        var list = new List<BlockedRule>();
        try
        {
            Ensure();
            foreach (dynamic r in _policy.Rules)
            {
                try
                {
                    string name = r.Name;
                    if (name != null && name.StartsWith(Prefix, StringComparison.Ordinal))
                        list.Add(new BlockedRule(name, r.ApplicationName ?? ""));
                }
                catch { /* 跳过异常单条 */ }
            }
            Available = true;
        }
        catch (Exception ex)
        {
            Available = false;
            LastError = ex.Message;
        }
        return list;
    }

    public bool RuleExists(string name) => ListRules().Any(r => r.Name == name);

    public void RemoveRule(string name)
    {
        Ensure();
        _policy.Rules.Remove(name);
    }

    public void UnblockApp(string path)
    {
        foreach (var r in ListRules())
            if (string.Equals(r.AppPath, path, StringComparison.OrdinalIgnoreCase))
                RemoveRule(r.Name);
    }
}
