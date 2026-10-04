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
    public struct RECT { public int L, T, R, B; }
}
"@
[Win]::SetProcessDPIAware() | Out-Null
New-Item -ItemType Directory -Force -Path $Dir | Out-Null

function Shot([string]$name) {
    $p = Get-Process NetWatch | Where-Object { $_.MainWindowHandle -ne 0 } | Select-Object -First 1
    $r = New-Object Win+RECT
    [Win]::GetWindowRect($p.MainWindowHandle, [ref]$r) | Out-Null
    $w = $r.R - $r.L; $h = $r.B - $r.T
    $bmp = New-Object System.Drawing.Bitmap $w, $h
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.CopyFromScreen($r.L, $r.T, 0, 0, $bmp.Size)
    $out = Join-Path $Dir $name
    $bmp.Save($out, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Output "saved $out"
}

$root = [System.Windows.Automation.AutomationElement]::RootElement
$nid = (Get-Process NetWatch | Select-Object -First 1).Id
$cond = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ProcessIdProperty, $nid)
$win = $root.FindFirst([System.Windows.Automation.TreeScope]::Children, $cond)
if (-not $win) { throw "UIA: NetWatch window not found (pid=$nid)" }

function FindByName([string]$name) {
    $c = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::NameProperty, $name)
    return $win.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $c)
}

# 取消「仅看可疑」
$cb = FindByName "仅看可疑"
if ($cb) {
    $tp = $cb.GetCurrentPattern([System.Windows.Automation.TogglePattern]::Pattern)
    if ($tp.Current.ToggleState -eq [System.Windows.Automation.ToggleState]::On) { $tp.Toggle() }
    Start-Sleep -Milliseconds 600
}

# 切到总览
$tab = FindByName "总览"
($tab.GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern)).Select()
Start-Sleep -Milliseconds 1500

# 在进程表里找 svchost 行优先选中，否则选第一行
$dg = $win.FindFirst([System.Windows.Automation.TreeScope]::Descendants,
    (New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ClassNameProperty, "DataGrid")))
if ($dg) {
    $rowCond = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::DataItem)
    $rows = $dg.FindAll([System.Windows.Automation.TreeScope]::Descendants, $rowCond)
    $target = $null
    foreach ($r in $rows) { if ($r.Current.Name -match 'svchost') { $target = $r; break } }
    if (-not $target -and $rows.Count -gt 0) { $target = $rows[0] }
    if ($target) {
        ($target.GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern)).Select()
        Write-Output ("selected: " + $target.Current.Name)
        Start-Sleep -Milliseconds 2500
    } else { Write-Output "no rows" }
}
Shot "p1-svchost.png"
Write-Output "done"
