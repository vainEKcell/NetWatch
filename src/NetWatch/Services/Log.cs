using System.IO;

namespace NetWatch.Services;

/// 极简文件日志：%LOCALAPPDATA%\NetWatch\NetWatch.log
public static class Log
{
    private static readonly object Gate = new();
    public static string FilePath { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "NetWatch", "NetWatch.log");

    static Log()
    {
        try { Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!); } catch { }
    }

    public static void Info(string msg) => Write("INFO", msg, null);
    public static void Error(string msg, Exception? ex = null) => Write("ERROR", msg, ex);

    private static void Write(string level, string msg, Exception? ex)
    {
        try
        {
            lock (Gate)
                File.AppendAllText(FilePath,
                    $"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} [{level}] {msg}{(ex == null ? "" : $"\n  {ex.GetType().Name}: {ex.Message}\n  {ex.StackTrace}")}\n");
        }
        catch { /* 日志失败不影响主流程 */ }
    }
}
