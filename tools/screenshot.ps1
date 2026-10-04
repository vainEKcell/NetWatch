param([string]$OutFile = "S:\ZWorker\NetWatch\verify\window.png")
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class Win {
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
    [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
    public struct RECT { public int L, T, R, B; }
}
"@
[Win]::SetProcessDPIAware() | Out-Null

$p = Get-Process NetWatch -ErrorAction Stop | Where-Object { $_.MainWindowHandle -ne 0 } | Select-Object -First 1
if (-not $p) { throw "NetWatch window not found" }
$hwnd = $p.MainWindowHandle
[Win]::SetForegroundWindow($hwnd) | Out-Null
Start-Sleep -Milliseconds 800

$r = New-Object Win+RECT
[Win]::GetWindowRect($hwnd, [ref]$r) | Out-Null
$w = $r.R - $r.L; $h = $r.B - $r.T
Write-Output "rect: $($r.L),$($r.T) ${w}x${h}"

if ($w -le 0 -or $h -le 0) { throw "bad rect" }
$bmp = New-Object System.Drawing.Bitmap $w, $h
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.CopyFromScreen($r.L, $r.T, 0, 0, $bmp.Size)
New-Item -ItemType Directory -Force -Path (Split-Path $OutFile) | Out-Null
$bmp.Save($OutFile, [System.Drawing.Imaging.ImageFormat]::Png)
Write-Output "saved: $OutFile"
