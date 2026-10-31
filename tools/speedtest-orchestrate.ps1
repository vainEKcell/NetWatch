param()
$ErrorActionPreference = 'Continue'
$marker = "S:\ZWorker\NetWatch\verify\build-done.flag"
Remove-Item $marker -ErrorAction SilentlyContinue

Get-Process NetWatch -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 2
$deadline = (Get-Date).AddMinutes(5)
while ((Get-Date) -lt $deadline -and -not (Test-Path $marker)) { Start-Sleep -Seconds 2 }
if (-not (Test-Path $marker)) { Set-Content "S:\ZWorker\NetWatch\verify\speedtest-result.txt" "orchestrator: build never finished"; exit 1 }

Start-Process "S:\ZWorker\NetWatch\src\NetWatch\bin\Debug\net10.0-windows\NetWatch.exe"
$deadline = (Get-Date).AddSeconds(30)
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 1
    $p = Get-Process NetWatch -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowHandle -ne 0 } | Select-Object -First 1
    if ($p) { break }
}
if (-not $p) { Set-Content "S:\ZWorker\NetWatch\verify\speedtest-result.txt" "window never appeared"; exit 1 }
$out = @("window ok (pid $($p.Id))")
Start-Sleep -Seconds 3

Add-Type -AssemblyName UIAutomationClient
$root = [System.Windows.Automation.AutomationElement]::RootElement
$cond = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ProcessIdProperty, $p.Id)
$win = $root.FindFirst([System.Windows.Automation.TreeScope]::Children, $cond)
if (-not $win) { Set-Content "S:\ZWorker\NetWatch\verify\speedtest-result.txt" "UIA window not found"; exit 1 }

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
}

$btn = Find-ByName $win "开始网络体检" ([System.Windows.Automation.ControlType]::Button)
if (-not $btn) { Set-Content "S:\ZWorker\NetWatch\verify\speedtest-result.txt" ($out -join '; ' + " | run button not found"); exit 1 }
($btn.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern)).Invoke()
$out += "check invoked"

# 等整个体检流程结束（最多 300 秒）：测速完成文本出现，或进度清空且结论出现
$deadline = (Get-Date).AddSeconds(300)
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 5
    $tc = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Text)
    $els = $win.FindAll([System.Windows.Automation.TreeScope]::Descendants, $tc)
    foreach ($el in $els) {
        $n = $el.Current.Name
        if ($n -match '下行|节点：|上行 |Mapping|NAT|链路容量|场景|优秀|良好|一般|较差') { $out += $n }
    }
    $joined = $out -join [char]10
    if ($joined -match '测速完成|均不可用') { break }
}
Set-Content -Path "S:\ZWorker\NetWatch\verify\speedtest-result.txt" -Value ($out -join [Environment]::NewLine) -Encoding UTF8
