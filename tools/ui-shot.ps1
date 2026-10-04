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
$pid2 = (Get-Process NetWatch | Select-Object -First 1).Id
$cond = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ProcessIdProperty, $pid2)
$win = $root.FindFirst([System.Windows.Automation.TreeScope]::Children, $cond)
if (-not $win) { throw "UIA: NetWatch window not found" }

function FindByName([string]$name) {
    $c = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::NameProperty, $name)
    return $win.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $c)
}

# 1) 取消「仅看可疑」过滤
$cb = FindByName "仅看可疑"
if ($cb) {
    $tp = $cb.GetCurrentPattern([System.Windows.Automation.TogglePattern]::Pattern)
    if ($tp.Current.ToggleState -eq [System.Windows.Automation.ToggleState]::On) { $tp.Toggle() }
    Start-Sleep -Milliseconds 800
    Write-Output "flag-filter: off"
} else { Write-Output "flag-filter: checkbox not found" }

# 2) 切到总览
$tab = FindByName "总览"
($tab.GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern)).Select()
Start-Sleep -Milliseconds 1500

# 3) 选中进程表第一行
$dg = $win.FindFirst([System.Windows.Automation.TreeScope]::Descendants,
    (New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ClassNameProperty, "DataGrid")))
if ($dg) {
    $rowCond = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::DataItem)
    $row = $dg.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $rowCond)
    if ($row) {
        ($row.GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern)).Select()
        Write-Output ("selected row: " + $row.Current.Name)
        Start-Sleep -Milliseconds 2000
    } else { Write-Output "no rows in grid" }
} else { Write-Output "no datagrid" }

Shot "tab-overview2.png"

# 4) DNS 页验证 IP 归一化
$tab = FindByName "DNS 安全"
($tab.GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern)).Select()
Start-Sleep -Milliseconds 2500
Shot "tab-dns2.png"

# 5) 目的地页验证域名标注
$tab = FindByName "目的地排行"
($tab.GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern)).Select()
Start-Sleep -Milliseconds 1500
Shot "tab-dest2.png"
Write-Output "done"
