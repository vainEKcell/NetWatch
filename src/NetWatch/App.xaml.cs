using System.Threading;
using System.Windows;
using NetWatch.Services;

namespace NetWatch;

public partial class App : Application
{
    private static Mutex? _mutex;

    protected override void OnStartup(StartupEventArgs e)
    {
        _mutex = new Mutex(true, "NetWatch_SingleInstance", out var fresh);
        if (!fresh)
        {
            MessageBox.Show(L10n.T("msg.alreadyRunning"), "NetWatch",
                MessageBoxButton.OK, MessageBoxImage.Information);
            Shutdown();
            return;
        }

        // 语言与主题在 MainWindow 加载前应用，避免闪烁
        var settings = AppSettings.Load();
        L10n.Apply(settings.Language);
        ThemeService.Apply(settings.Theme);

        DispatcherUnhandledException += (_, args) =>
        {
            Log.Error("UI 未处理异常（含内层链）", Flatten(args.Exception));
            MessageBox.Show(
                L10n.T("msg.uiError", args.Exception.Message, Log.FilePath),
                "NetWatch", MessageBoxButton.OK, MessageBoxImage.Error);
            args.Handled = true;
        };
        AppDomain.CurrentDomain.UnhandledException += (_, args) =>
            Log.Error("AppDomain 未处理异常", Flatten(args.ExceptionObject as Exception));
        TaskScheduler.UnobservedTaskException += (_, args) =>
            Log.Error("Task 未观察异常", Flatten(args.Exception));

        base.OnStartup(e);
    }

    private static Exception? Flatten(Exception? ex)
    {
        // 返回最内层异常，日志里才能看到真实原因
        while (ex?.InnerException != null) ex = ex.InnerException;
        return ex;
    }
}
