using System.Globalization;
using System.Windows;

namespace NetWatch.Services;

/// 轻量本地化：字符串表在 Themes/Strings.zh.xaml 与 Strings.en.xaml，
/// 运行时整体切换 ResourceDictionary（XAML DynamicResource 即时生效，C# 侧用 T()）。
public static class L10n
{
    /// "auto" 按系统 UI 语言解析；否则 zh / en
    public static string Normalize(string? language)
    {
        if (language == "zh" || language == "en") return language;
        try
        {
            return CultureInfo.CurrentUICulture.TwoLetterISOLanguageName
                .Equals("zh", StringComparison.OrdinalIgnoreCase) ? "zh" : "en";
        }
        catch { return "zh"; }
    }

    public static void Apply(string? language)
    {
        var lang = Normalize(language);
        var uri = new Uri($"pack://application:,,,/Themes/Strings.{lang}.xaml");
        var md = Application.Current.Resources.MergedDictionaries;
        for (int i = md.Count - 1; i >= 0; i--)
            if (md[i].Source != null && md[i].Source!.OriginalString.Contains("Strings."))
                md.RemoveAt(i);
        md.Add(new ResourceDictionary { Source = uri });
        Loc.Instance.Refresh();
    }

    /// 取词；带参数时按 string.Format 填充
    public static string T(string key, params object[] args)
    {
        var v = Application.Current?.TryFindResource(key) as string ?? key;
        return args.Length == 0 ? v : string.Format(v, args);
    }
}
