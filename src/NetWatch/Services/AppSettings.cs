using System.IO;
using System.Text.Json;

namespace NetWatch.Services;

/// 应用设置（%LOCALAPPDATA%\NetWatch\settings.json）
public sealed class AppSettings
{
    /// 行为基线保留天数（0 = 不限）
    public int BaselineRetentionDays { get; set; } = 90;
    /// 原始证据流保留天数（0 = 不限）
    public int EvidenceRetentionDays { get; set; } = 7;
    /// 证据目录容量硬顶（MB），超出按最旧删除
    public int EvidenceMaxSizeMB { get; set; } = 512;
    /// 隐私模式：暂停基线学习（证据流照常）
    public bool BaselinePaused { get; set; }

    public static string Dir { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NetWatch");
    public static string SettingsPath { get; } = Path.Combine(Dir, "settings.json");
    public static string DbPath { get; } = Path.Combine(Dir, "baseline.db");
    public static string EvidenceDir { get; } = Path.Combine(Dir, "evidence");

    public static AppSettings Load()
    {
        try
        {
            if (File.Exists(SettingsPath))
                return JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(SettingsPath)) ?? new AppSettings();
        }
        catch (Exception ex) { Log.Error("读取设置失败，使用默认值", ex); }
        return new AppSettings();
    }

    public void Save()
    {
        try
        {
            Directory.CreateDirectory(Dir);
            File.WriteAllText(SettingsPath, JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch (Exception ex) { Log.Error("保存设置失败", ex); }
    }
}
