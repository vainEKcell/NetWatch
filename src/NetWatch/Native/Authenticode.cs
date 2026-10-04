using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using NetWatch.Models;
using NetWatch.Services;

namespace NetWatch.Native;

/// Authenticode 数字签名验证（wintrust / WinVerifyTrust），结果按文件路径缓存
public static class Authenticode
{
    private static readonly ConcurrentDictionary<string, (SignatureState State, string? Subject)> Cache =
        new(StringComparer.OrdinalIgnoreCase);

    public static (SignatureState State, string? Subject) Verify(string path)
        => Cache.GetOrAdd(path, static p => VerifyCore(p));

    private static (SignatureState, string?) VerifyCore(string path)
    {
        // x64 WINTRUST_DATA 布局（88 字节），按偏移手工填充，避免结构体封送歧义：
        //  0  cbStruct(4)          8  pPolicyCallbackData     16 pSIPClientData
        // 24  dwUIChoice(4)       28 fdwRevocationChecks(4)  32 dwUnionChoice(4)
        // 40  union.pFile         48 dwStateAction(4)        56 hWVTStateData
        // 64  union2(pUsage)      72 dwUIContext(4)          80 pSignatureSettings
        const uint TRUST_E_NOSIGNATURE = 0x800B0100;
        const uint CERT_E_UNTRUSTEDROOT = 0x800B0109;
        const uint CERT_E_CHAINING = 0x800B010A;
        const uint TRUST_E_EXPLICIT_DISTRUST = 0x800B0111;

        uint ret;
        IntPtr fileInfo = IntPtr.Zero, filePath = IntPtr.Zero, trustData = IntPtr.Zero;
        try
        {
            const int fiSize = 32; // cbStruct + 3 指针
            fileInfo = Marshal.AllocHGlobal(fiSize);
            filePath = Marshal.StringToCoTaskMemUni(path);
            Marshal.WriteInt32(fileInfo, 0, fiSize);
            Marshal.WriteIntPtr(fileInfo, 8, filePath);
            Marshal.WriteIntPtr(fileInfo, 16, IntPtr.Zero);
            Marshal.WriteIntPtr(fileInfo, 24, IntPtr.Zero);

            const int tdSize = 88;
            trustData = Marshal.AllocHGlobal(tdSize);
            for (int off = 0; off < tdSize; off += 8) Marshal.WriteInt64(trustData, off, 0);
            Marshal.WriteInt32(trustData, 0, tdSize);
            Marshal.WriteInt32(trustData, 24, 2);  // dwUIChoice = WTD_UI_NONE
            Marshal.WriteInt32(trustData, 28, 0);  // fdwRevocationChecks = WTD_REVOKE_NONE
            Marshal.WriteInt32(trustData, 32, 1);  // dwUnionChoice = WTD_CHOICE_FILE
            Marshal.WriteIntPtr(trustData, 40, fileInfo);
            Marshal.WriteInt32(trustData, 48, 0);  // dwStateAction = WTD_STATEACTION_IGNORE
            Marshal.WriteInt32(trustData, 72, 0);  // dwUIContext = 0

            var action = NativeMethods.WinTrustActionId;
            ret = NativeMethods.WinVerifyTrust(IntPtr.Zero, ref action, trustData);
        }
        catch
        {
            return (SignatureState.Unknown, null);
        }
        finally
        {
            if (fileInfo != IntPtr.Zero) Marshal.FreeHGlobal(fileInfo);
            if (filePath != IntPtr.Zero) Marshal.FreeCoTaskMem(filePath);
            if (trustData != IntPtr.Zero) Marshal.FreeHGlobal(trustData);
        }

        string? subject = TryGetSubject(path);

        if (ret == 0) return (SignatureState.Valid, subject);
        if (ret == TRUST_E_NOSIGNATURE) return (SignatureState.Unsigned, null);
        if (ret is CERT_E_UNTRUSTEDROOT or CERT_E_CHAINING or TRUST_E_EXPLICIT_DISTRUST)
            return (SignatureState.Untrusted, subject);
        // 过期 / 吊销 / 摘要不符（文件被篡改）等
        return (SignatureState.Invalid, subject);
    }

    private static string? TryGetSubject(string path)
    {
        try
        {
            var cert = System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromSignedFile(path);
            var s = cert.Subject ?? "";
            int cn = s.IndexOf("CN=", StringComparison.Ordinal);
            if (cn >= 0)
            {
                var rest = s[(cn + 3)..];
                int comma = rest.IndexOf(',');
                return comma > 0 ? rest[..comma].Trim() : rest.Trim();
            }
            return s;
        }
        catch { return null; }
    }
}
