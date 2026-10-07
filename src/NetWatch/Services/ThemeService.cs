using System.Windows;
using NetWatch.ViewModels;

namespace NetWatch.Services;

/// 主题应用：Palette.<dark|light>.xaml 整体切换 + 同步 VM 侧可变画刷。
/// auto = 读取系统"应用深浅"偏好；后续系统主题变化由 VM 的周期检查触发重算。
public static class ThemeService
{
    private static string _requested = "auto";
    private static string _lastApplied = "";

    public static bool SystemPrefersLight()
    {
        try
        {
            using var k = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
            return k?.GetValue("AppsUseLightTheme") is int v && v == 1;
        }
        catch { return false; }
    }

    private static string Resolve(string theme) =>
        theme == "dark" || theme == "light" ? theme : (SystemPrefersLight() ? "light" : "dark");

    public static void Apply(string theme)
    {
        _requested = theme;
        var t = Resolve(theme);
        if (t == _lastApplied) return;
        _lastApplied = t;

        var md = Application.Current.Resources.MergedDictionaries;
        for (int i = md.Count - 1; i >= 0; i--)
            if (md[i].Source?.OriginalString.Contains("Palette.") == true)
                md.RemoveAt(i);
        md.Add(new ResourceDictionary { Source = new Uri($"pack://application:,,,/Themes/Palette.{t}.xaml") });
        UiBrushes.Refresh(t);
    }
}
