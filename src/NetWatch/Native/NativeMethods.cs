using System.Runtime.InteropServices;

namespace NetWatch.Native;

/// iphlpapi 连接表 / shell32 图标 / wintrust 签名验证 的 P/Invoke 声明
internal static partial class NativeMethods
{
    public const uint AF_INET = 2;
    public const uint AF_INET6 = 23;
    /// TCP_TABLE_OWNER_PID_ALL（注意：1 是 BASIC_CONNECTIONS，返回不带 PID 的 20 字节行）
    public const uint TCP_TABLE_OWNER_PID_ALL = 5;
    public const uint UDP_TABLE_OWNER_PID = 1;

    [DllImport("iphlpapi.dll", SetLastError = true)]
    public static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize, bool bOrder, uint ulAf, uint TableClass, uint Reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    public static extern uint GetExtendedUdpTable(IntPtr pUdpTable, ref int pdwSize, bool bOrder, uint ulAf, uint TableClass, uint Reserved);

    // ---------- Authenticode（wintrust） ----------

    // WINTRUST_ACTION_GENERIC_VERIFY_V2
    public static readonly Guid WinTrustActionId = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    [DllImport("wintrust.dll")]
    public static extern uint WinVerifyTrust(IntPtr hWnd, ref Guid pgActionID, IntPtr pWVTData);

    // ---------- 进程图标（shell32） ----------

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct SHFILEINFOW
    {
        public IntPtr hIcon;
        public int iIcon;
        public uint dwAttributes;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szDisplayName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 80)] public string szTypeName;
    }

    private const uint SHGFI_ICON = 0x000000100;
    private const uint SHGFI_LARGEICON = 0x000000000;

    [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr SHGetFileInfo(string pszPath, uint dwFileAttributes, ref SHFILEINFOW psfi, uint cbFileInfo, uint uFlags);

    [DllImport("user32.dll")]
    private static extern bool DestroyIcon(IntPtr hIcon);

    public static IntPtr GetFileIconHandle(string path)
    {
        var info = new SHFILEINFOW();
        IntPtr res = SHGetFileInfo(path, 0, ref info, (uint)Marshal.SizeOf<SHFILEINFOW>(), SHGFI_ICON | SHGFI_LARGEICON);
        return res != IntPtr.Zero ? info.hIcon : IntPtr.Zero;
    }

    public static void FreeIconHandle(IntPtr hIcon)
    {
        if (hIcon != IntPtr.Zero) DestroyIcon(hIcon);
    }

    // ---------- WinHTTP 默认代理（网络配置页） ----------

    [StructLayout(LayoutKind.Sequential)]
    private struct WINHTTP_PROXY_INFO
    {
        public uint AccessType;
        public IntPtr Proxy;
        public IntPtr ProxyBypass;
    }

    [DllImport("winhttp.dll", SetLastError = true)]
    private static extern bool WinHttpGetDefaultProxyConfiguration(ref WINHTTP_PROXY_INFO pInfo);

    /// 返回 WinHTTP 层默认代理描述（"DIRECT" 或代理地址）
    public static string GetWinHttpProxy()
    {
        try
        {
            var info = new WINHTTP_PROXY_INFO();
            if (!WinHttpGetDefaultProxyConfiguration(ref info)) return "未知";
            try
            {
                if (info.AccessType == 1) return "直接连接（无代理）";
                string proxy = info.Proxy != IntPtr.Zero ? Marshal.PtrToStringUni(info.Proxy) ?? "" : "";
                return string.IsNullOrEmpty(proxy) ? "直接连接（无代理）" : proxy;
            }
            finally
            {
                if (info.Proxy != IntPtr.Zero) Marshal.FreeHGlobal(info.Proxy);
                if (info.ProxyBypass != IntPtr.Zero) Marshal.FreeHGlobal(info.ProxyBypass);
            }
        }
        catch { return "读取失败"; }
    }
}
