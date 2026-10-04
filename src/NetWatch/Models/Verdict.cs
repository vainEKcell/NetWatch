namespace NetWatch.Models;

/// 判定状态：UNKNOWN 是合法且重要的输出——证据不足时绝不强行定性
public enum VerdictStatus : byte
{
    Normal,     // 有正面证据（签名有效+常规位置+行为无异常）
    Unknown,    // 已观察到网络行为，但证据不足以判断
    Attention,  // 存在值得关注的特征（单项中等或多项组合）
    HighRisk,   // 多项独立特征组合异常，建议立即核查
}

/// 单条证据：陈述 + 依据 + 误报可能/缺失信息
public sealed record EvidenceItem(
    string Statement,
    string? Basis,
    string? Caveat,
    int Weight);   // 1=弱 2=中 3=强

/// 判定结果：状态 + 摘要 + 完整证据链
public sealed class Verdict
{
    public VerdictStatus Status { get; set; }
    public string Summary { get; set; } = "";
    public List<EvidenceItem> Evidence { get; } = new();

    public byte RiskByte => Status switch
    {
        VerdictStatus.HighRisk => 3,
        VerdictStatus.Attention => 2,
        VerdictStatus.Unknown => 1,
        _ => 0,
    };
}
