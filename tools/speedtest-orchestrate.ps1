param()
$ErrorActionPreference = 'Continue'
$marker = "S:\ZWorker\NetWatch\verify\build-done.flag"
Remove-Item $marker -ErrorAction SilentlyContinue

# 1) 杀旧实例（本脚本是提权的，能杀）
Get-Process NetWatch -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 2

# 2) 等主会话完成构建（最多 5 分钟）
$deadline = (Get-Date).AddMinutes(5)
while ((Get-Date) -lt $deadline -and -not (Test-Path $marker)) { Start-Sleep -Seconds 2 }
if (-not (Test-Path $marker)) { Set-Content "S:\ZWorker\NetWatch\verify\speedtest-result.txt" "orchestrator: build never finished"; exit 1 }

# 3) 启动新构建的 app
Start-Process "S:\ZWorker\NetWatch\src\NetWatch\bin\Debug\net10.0-windows\NetWatch.exe"
$deadline = (Get-Date).AddSeconds(30)
$hwnd = 0
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 1
    $p = Get-Process NetWatch -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowHandle -ne 0 } | Select-Object -First 1
    if ($p) { $hwnd = $p.MainWindowHandle; break }
}
if ($hwnd -eq 0) { Set-Content "S:\ZWorker\NetWatch\verify\speedtest-result.txt" "window never appeared"; exit 1 }
$out = @("window ok (pid $($p.Id))")
Start-Sleep -Seconds 3

Add-Type -AssemblyName UIAutomationClient
$root = [System.Windows.Automation.AutomationElement]::RootElement
$cond = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ProcessIdProperty, $p.Id)
$win = $root.FindFirst([System.Windows.Automation.TreeScope]::Children, $cond)
if (-not $win) { Set-Content "S:\ZWorker\NetWatch\verify\speedtest-result.txt" ($out -join '; ' + " | UIA window not found"); exit 1 }

function Find-ByName($parent, $name, $ctlType) {
    $c1 = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::NameProperty, $name)
    $c2 = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, $ctlType)
    $and = New-Object System.Windows.Automation.AndCondition($c1, $c2)
    return $parent.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $and)
}

$nav = Find-ByName $win "网络体检" ([System.Windows.Automation.ControlType]::ListItem)
if ($nav) {
    ($nav.GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern)).Select()
    Start-Sleep -Milliseconds 800
    $out += "nav ok"
} else { $out += "nav NOT found" }

$btn = Find-ByName $win "测下行" ([System.Windows.Automation.ControlType]::Button)
if (-not $btn) { Set-Content "S:\ZWorker\NetWatch\verify\speedtest-result.txt" ($out -join '; ' + " | button not found"); exit 1 }
($btn.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern)).Invoke()
$out += "invoked"

$deadline = (Get-Date).AddSeconds(75)
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 3
    $tc = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Text)
    $els = $win.FindAll([System.Windows.Automation.TreeScope]::Descendants, $tc)
    foreach ($el in $els) {
        $n = $el.Current.Name
        if ($n -match '下行最优|均失败|正在从|Mbps|Gbps|失败') { $out += $n }
    }
    if (($out -join [char]10) -match '下行最优|均失败') { break }
}
# 5) 测上行
$btnUp = Find-ByName $win "测上行" ([System.Windows.Automation.ControlType]::Button)
if ($btnUp) {
    ($btnUp.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern)).Invoke()
    $out += "up-invoked"
    $deadline = (Get-Date).AddSeconds(260)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 5
        $tc = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Text)
        $els = $win.FindAll([System.Windows.Automation.TreeScope]::Descendants, $tc)
        foreach ($el in $els) { $n = $el.Current.Name; if ($n -match "上行参考值|上行没测成") { $out += $n } }
        if (($out -join [char]10) -match "上行参考值|上行没测成") { break }
    }
}
Set-Content -Path "S:/ZWorker/NetWatch/verify/speedtest-result.txt" -Value ($out -join [Environment]::NewLine) -Encoding UTF8
