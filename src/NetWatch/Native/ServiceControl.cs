using System.Runtime.InteropServices;

namespace NetWatch.Native;

/// advapi32 服务控制器：枚举系统服务并与 PID 关联（svchost 归因的关键）
public static class ServiceControl
{
    private const uint SC_MANAGER_ENUMERATE_SERVICE = 0x0004;
    private const uint SERVICE_WIN32 = 0x00000030;   // OWN(0x10) | SHARE(0x20) 进程服务
    private const uint SERVICE_STATE_ALL = 3;
    private const uint SC_ENUM_PROCESS_INFO = 0;
    private const int ERROR_MORE_DATA = 234;

    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    private struct ENUM_SERVICE_STATUS_PROCESS
    {
        public IntPtr lpServiceName;
        public IntPtr lpDisplayName;
        public SERVICE_STATUS_PROCESS ServiceStatusProcess;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SERVICE_STATUS_PROCESS
    {
        public uint dwServiceType;
        public uint dwCurrentState;
        public uint dwControlsAccepted;
        public uint dwWin32ExitCode;
        public uint dwServiceSpecificExitCode;
        public uint dwCheckPoint;
        public uint dwWaitHint;
        public uint dwProcessId;
        public uint dwServiceFlags;
    }

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenSCManager(string? lpMachineName, string? lpDatabaseName, uint dwDesiredAccess);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CloseServiceHandle(IntPtr hSCObject);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool EnumServicesStatusEx(
        IntPtr hSCManager, uint InfoLevel, uint dwServiceType, uint dwServiceState,
        IntPtr lpServices, uint cbBufSize, out uint pcbBytesNeeded,
        out uint lpServicesReturned, out uint lpResumeHandle, IntPtr pszGroupName);

    public sealed record ServiceInfo(string Name, string DisplayName, int Pid);

    /// 枚举所有 Win32 服务及其宿主 PID。失败返回空表。
    public static List<ServiceInfo> EnumServices()
    {
        var result = new List<ServiceInfo>(256);
        IntPtr scm = OpenSCManager(null, null, SC_MANAGER_ENUMERATE_SERVICE);
        if (scm == IntPtr.Zero) return result;
        try
        {
            uint size = 64 * 1024;
            IntPtr buf = Marshal.AllocHGlobal((IntPtr)size);
            try
            {
                uint returned;
                for (;;)
                {
                    bool ok = EnumServicesStatusEx(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                        buf, size, out uint needed, out returned, out _, IntPtr.Zero);
                    if (ok) break;
                    if (Marshal.GetLastWin32Error() != ERROR_MORE_DATA) return result;
                    Marshal.FreeHGlobal(buf);
                    size = needed + 4096;
                    buf = Marshal.AllocHGlobal((IntPtr)size);
                }

                int stride = Marshal.SizeOf<ENUM_SERVICE_STATUS_PROCESS>();
                for (uint i = 0; i < returned; i++)
                {
                    IntPtr p = buf + (int)(i * stride);
                    var essp = Marshal.PtrToStructure<ENUM_SERVICE_STATUS_PROCESS>(p);
                    string? name = Marshal.PtrToStringUni(essp.lpServiceName);
                    string? disp = Marshal.PtrToStringUni(essp.lpDisplayName);
                    int pid = (int)essp.ServiceStatusProcess.dwProcessId;
                    if (!string.IsNullOrEmpty(name))
                        result.Add(new ServiceInfo(name, disp ?? name, pid));
                }
            }
            finally { Marshal.FreeHGlobal(buf); }
        }
        finally { CloseServiceHandle(scm); }
        return result;
    }
}
