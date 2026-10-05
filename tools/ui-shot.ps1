param([string]$Dir = "S:\ZWorker\NetWatch\verify", [string]$PidText = "2068")
$ErrorActionPreference = 'Stop'

function Main {
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
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
    public struct RECT { public int L, T, R, B; }
}
"@
    [Win]::SetProcessDPIAware() | Out-Null
    New-Item -ItemType Directory -Force -Path $Dir | Out-Null

    $netProc = Get-Process NetWatch | Where-Object { $_.MainWindowHandle -ne 0 } | Select-Object -First 1
    if (-not $netProc) { throw "NetWatch has no window handle" }
    if (-not [Win]::IsWindowVisible($netProc.MainWindowHandle)) {
        [Win]::ShowWindow($netProc.MainWindowHandle, 9) | Out-Null   # SW_RESTORE
        Start-Sleep -Milliseconds 800
        Log "window was hidden, restored"
    }
    [Win]::SetForegroundWindow($netProc.MainWindowHandle) | Out-Null

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
    $logFile = "S:\ZWorker\NetWatch\verify\uilog.txt"
    function Log([string]$m) { Add-Content -Path $logFile -Value $m -Encoding UTF8 }
    Log "=== run $(Get-Date -Format HH:mm:ss) pid=$nid ==="
    $cond = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ProcessIdProperty, $nid)
    $win = $root.FindFirst([System.Windows.Automation.TreeScope]::Children, $cond)
    if (-not $win) { throw "UIA: NetWatch window not found (pid=$nid)" }
    Log ("window: " + $win.Current.Name)

    function FindByName([string]$name) {
        $c = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::NameProperty, $name)
        return $win.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $c)
    }

    $cb = FindByName "仅看可疑"
    if ($cb) {
        $tp = $cb.GetCurrentPattern([System.Windows.Automation.TogglePattern]::Pattern)
        Log ("checkbox 仅看可疑 found, state=" + $tp.Current.ToggleState)
        if ($tp.Current.ToggleState -eq [System.Windows.Automation.ToggleState]::On) { $tp.Toggle(); Start-Sleep -Milliseconds 800 }
    } else { Log "checkbox 仅看可疑 NOT found" }

    $tab = FindByName "总览"
    ($tab.GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern)).Select()
    Start-Sleep -Milliseconds 1200
    Log "tab 总览 selected"

    $dg = $null
    $gridCond = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ClassNameProperty, "DataGrid")
    $grids = $win.FindAll([System.Windows.Automation.TreeScope]::Descendants, $gridCond)
    Log ("datagrids found: " + $grids.Count)
    $rowCond0 = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::DataItem)
    foreach ($g in $grids) {
        $c = $g.FindAll([System.Windows.Automation.TreeScope]::Descendants, $rowCond0).Count
        Log ("  grid rows: " + $c)
        if ($c -gt 0 -and -not $dg) { $dg = $g; $rows = $g.FindAll([System.Windows.Automation.TreeScope]::Descendants, $rowCond0) }
    }
    if (-not $dg) {
        # 兜底：可能搜索框有残留过滤词，清空所有 Edit 后重试一次
        $editCond = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Edit)
        foreach ($e in $win.FindAll([System.Windows.Automation.TreeScope]::Descendants, $editCond)) {
            try { ($e.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern)).SetValue(""); Log "cleared an Edit" } catch { }
        }
        Start-Sleep -Milliseconds 1500
        foreach ($g in $grids) {
            $c = $g.FindAll([System.Windows.Automation.TreeScope]::Descendants, $rowCond0).Count
            Log ("  retry grid rows: " + $c)
            if ($c -gt 0 -and -not $dg) { $dg = $g; $rows = $g.FindAll([System.Windows.Automation.TreeScope]::Descendants, $rowCond0) }
        }
    }
    if (-not $dg) { throw "no datagrid with rows" }
    $rowCond = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::DataItem)
    $rows = $dg.FindAll([System.Windows.Automation.TreeScope]::Descendants, $rowCond)
    Log ("visible rows: " + $rows.Count)
    $row = $null; $pickedPid = ""
    foreach ($r in $rows) {
        $texts = $r.FindAll([System.Windows.Automation.TreeScope]::Descendants,
            (New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Text)))
        $names = @($texts | ForEach-Object { $_.Current.Name })
        foreach ($want in @("2472", "5960", "6100")) {
            if ($names -contains $want) { $row = $r; $pickedPid = $want; break }
        }
        if ($row) { break }
    }
    if (-not $row) {
        if ($rows.Count -gt 0) { $row = $rows[0]; $pickedPid = "first-row" }
    }
    if (-not $row) { throw "no rows visible" }
    ($row.GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern)).Select()
    Write-Output ("selected pid: " + $pickedPid)
    Start-Sleep -Milliseconds 2500

    Shot "p1-svchost2.png"

    # P5 信任流程验证：点击「✓ 信任此软件」→ 判定应变为客户信任
    $trustBtn = FindByName "✓ 信任此软件"
    if ($trustBtn) {
        ($trustBtn.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern)).Invoke()
        Log "trust invoked"
        Start-Sleep -Milliseconds 2500
        Shot "p5-trusted.png"
    } else { Log "trust button not found (可能已处于信任态)" }

    Write-Output "done"
}

try {
    Main
} catch {
    Add-Content -Path "S:\ZWorker\NetWatch\verify\uilog.txt" -Value ("ERROR: " + $_.ToString()) -Encoding UTF8
    throw
}
