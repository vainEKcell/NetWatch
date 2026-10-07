param([string]$Dir = "S:\ZWorker\NetWatch\verify")
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class Win {
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
    [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int cmd);
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

function SelTab([string]$name) {
    $root = [System.Windows.Automation.AutomationElement]::RootElement
    $netProc = Get-Process NetWatch | Where-Object { $_.MainWindowHandle -ne 0 } | Select-Object -First 1
    $cond = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ProcessIdProperty, $netProc.Id)
    $win = $root.FindFirst([System.Windows.Automation.TreeScope]::Children, $cond)
    if (-not $win) { throw "window not found" }
    $c = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::NameProperty, $name)
    $tab = $win.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $c)
    if (-not $tab) { throw "tab not found: $name" }
    ($tab.GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern)).Select()
    Start-Sleep -Milliseconds 1200
}

function SetTheme([string]$themeName) {
    $root = [System.Windows.Automation.AutomationElement]::RootElement
    $netProc = Get-Process NetWatch | Where-Object { $_.MainWindowHandle -ne 0 } | Select-Object -First 1
    $cond = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ProcessIdProperty, $netProc.Id)
    $win = $root.FindFirst([System.Windows.Automation.TreeScope]::Children, $cond)
    $comboCond = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::AutomationIdProperty, "CbTheme")
    $combo = $win.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $comboCond)
    if (-not $combo) { throw "theme combo not found" }
    ($combo.GetCurrentPattern([System.Windows.Automation.ExpandCollapsePattern]::Pattern)).Expand()
    Start-Sleep -Milliseconds 700
    $itemCond = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::NameProperty, $themeName)
    $item = $combo.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $itemCond)
    if (-not $item) { throw "theme item not found: $themeName" }
    ($item.GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern)).Select()
    ($combo.GetCurrentPattern([System.Windows.Automation.ExpandCollapsePattern]::Pattern)).Collapse()
    Start-Sleep -Milliseconds 1500
    Log "theme set: $themeName"
}

try {
    $netProc = Get-Process NetWatch | Where-Object { $_.MainWindowHandle -ne 0 } | Select-Object -First 1
    if (-not [Win]::IsWindowVisible($netProc.MainWindowHandle)) {
        [Win]::ShowWindow($netProc.MainWindowHandle, 9) | Out-Null
        Start-Sleep -Milliseconds 600
    }

    SelTab "设置"
    SetTheme "浅色"
    Shot "p-theme-light.png"

    SelTab "目的地排行"
    Shot "p-dest-headers-light.png"

    SelTab "设置"
    SetTheme "深色"
    Write-Output "done"
} catch {
    Log ("ERROR: " + $_.ToString())
    throw
}
