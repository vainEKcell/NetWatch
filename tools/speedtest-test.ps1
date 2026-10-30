param()
$ErrorActionPreference = 'Continue'
Add-Type -AssemblyName UIAutomationClient
$logFile = "S:\ZWorker\NetWatch\verify\speedtest-result.txt"
$out = @()

# 0) 旧实例：杀掉（窗口可能在托盘隐藏）
Get-Process NetWatch -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 2

# 1) 启动
Start-Process "S:\ZWorker\NetWatch\src\NetWatch\bin\Debug\net10.0-windows\NetWatch.exe"
$deadline = (Get-Date).AddSeconds(30)
$hwnd = 0
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 1
    $p = Get-Process NetWatch -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowHandle -ne 0 } | Select-Object -First 1
    if ($p) { $hwnd = $p.MainWindowHandle; break }
}
if ($hwnd -eq 0) { Set-Content $logFile "window never appeared"; exit 1 }
$out += "window ok (pid $($p.Id))"
Start-Sleep -Seconds 3

$root = [System.Windows.Automation.AutomationElement]::RootElement
$cond = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ProcessIdProperty, $p.Id)
$win = $root.FindFirst([System.Windows.Automation.TreeScope]::Children, $cond)
if (-not $win) { Set-Content $logFile ($out -join '; ' + " | UIA window not found"); exit 1 }

function Find-ByName($parent, $name, $ctlType) {
    $c1 = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::NameProperty, $name)
    $c2 = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, $ctlType)
    $and = New-Object System.Windows.Automation.AndCondition($c1, $c2)
    return $parent.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $and)
}

# 2) 导航到 网络体检
$nav = Find-ByName $win "网络体检" ([System.Windows.Automation.ControlType]::ListItem)
if ($nav) {
    ($nav.GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern)).Select()
    Start-Sleep -Milliseconds 800
    $out += "nav ok"
} else { $out += "nav NOT found" }

# 3) 点 测下行
$btn = Find-ByName $win "测下行（多源）" ([System.Windows.Automation.ControlType]::Button)
if (-not $btn) {
    $bc = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Button)
    $btns = $win.FindAll([System.Windows.Automation.TreeScope]::Descendants, $bc)
    $names = @(); foreach ($b in $btns) { $names += $b.Current.Name }
    $out += ("buttons: " + ($names -join ' | '))
    Set-Content -Path $logFile -Value ($out -join [Environment]::NewLine) -Encoding UTF8
    exit 1
}
($btn.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern)).Invoke()
$out += "invoked"

# 4) 轮询结果（最多 75 秒）
$deadline = (Get-Date).AddSeconds(75)
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 3
    $tc = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Text)
    $els = $win.FindAll([System.Windows.Automation.TreeScope]::Descendants, $tc)
    foreach ($el in $els) {
        $n = $el.Current.Name
        if ($n -match '下行最优|均失败|测速源|正在从|Mbps|Gbps') { $out += $n }
    }
    $joined = $out -join [char]10
    if ($joined -match '下行最优|均失败') { break }
}
Set-Content -Path $logFile -Value ($out -join [Environment]::NewLine) -Encoding UTF8
Write-Output done
