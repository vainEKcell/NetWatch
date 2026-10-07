param([string]$Dir = "S:\ZWorker\NetWatch\verify")
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class Win {
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
    [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int cmd);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
    [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
    [DllImport("user32.dll")] public static extern void mouse_event(uint flags, uint dx, uint dy, uint data, UIntPtr extra);
    public struct RECT { public int L, T, R, B; }
}
"@
[Win]::SetProcessDPIAware() | Out-Null
New-Item -ItemType Directory -Force -Path $Dir | Out-Null
$logFile = "S:\ZWorker\NetWatch\verify\uilog.txt"
function Log([string]$m) { Add-Content -Path $logFile -Value $m -Encoding UTF8 }

function Shot([string]$name) {
    $p = Get-Process NetWatch | Where-Object { $_.MainWindowHandle -ne 0 } | Select-Object -First 1
    $r = New-Object Win+RECT
    [Win]::GetWindowRect($p.MainWindowHandle, [ref]$r) | Out-Null
    $w = $r.R - $r.L; $h = $r.B - $r.T
    $bmp = New-Object System.Drawing.Bitmap $w, $h
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.CopyFromScreen($r.L, $r.T, 0, 0, $bmp.Size)
    $bmp.Save((Join-Path $Dir $name), [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Output "saved $name"
}

function ClickAtRel([double]$fx, [double]$fy) {
    $p = Get-Process NetWatch | Where-Object { $_.MainWindowHandle -ne 0 } | Select-Object -First 1
    $r = New-Object Win+RECT
    [Win]::GetWindowRect($p.MainWindowHandle, [ref]$r) | Out-Null
    $x = [int]($r.L + ($r.R - $r.L) * $fx)
    $y = [int]($r.T + ($r.B - $r.T) * $fy)
    [Win]::SetCursorPos($x, $y) | Out-Null
    Start-Sleep -Milliseconds 150
    [Win]::mouse_event(2, 0, 0, 0, [UIntPtr]::Zero)
    [Win]::mouse_event(4, 0, 0, 0, [UIntPtr]::Zero)
    Log "clicked at $x,$y (rel $fx,$fy)"
}

try {
    $netProc = Get-Process NetWatch | Where-Object { $_.MainWindowHandle -ne 0 } | Select-Object -First 1
    if (-not [Win]::IsWindowVisible($netProc.MainWindowHandle)) {
        [Win]::ShowWindow($netProc.MainWindowHandle, 9) | Out-Null
        Start-Sleep -Milliseconds 600
    }
    [Win]::SetForegroundWindow($netProc.MainWindowHandle) | Out-Null
    Start-Sleep -Milliseconds 500

    # 总览页第一屏："↑ 累计"列头（窗口宽 ~49.7%、高 ~14.5%）
    ClickAtRel 0.497 0.145
    Start-Sleep -Milliseconds 1200
    Shot "p-sort-desc.png"
    ClickAtRel 0.497 0.145
    Start-Sleep -Milliseconds 1200
    Shot "p-sort-asc.png"
    Write-Output "done"
} catch {
    Log ("ERROR: " + $_.ToString())
    throw
}
