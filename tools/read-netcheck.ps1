param()
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName UIAutomationClient
$logFile = "S:\ZWorker\NetWatch\verify\netcheck-result.txt"
$netProc = Get-Process NetWatch | Where-Object { $_.MainWindowHandle -ne 0 } | Select-Object -First 1
if (-not $netProc) { Set-Content $logFile "NetWatch not running"; exit 1 }
$root = [System.Windows.Automation.AutomationElement]::RootElement
$cond = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ProcessIdProperty, $netProc.Id)
$win = $root.FindFirst([System.Windows.Automation.TreeScope]::Children, $cond)
if (-not $win) { Set-Content $logFile "window not found"; exit 1 }

# 抓窗口内所有 Text 元素里与体检相关的行
$cc = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Text)
$els = $win.FindAll([System.Windows.Automation.TreeScope]::Descendants, $cc)
$out = @()
foreach ($el in $els) {
    $n = $el.Current.Name
    if ($n -match 'NAT|外部|锥形|对称|公网直连|无法检测|检测数据不足|优秀|良好|一般|较差|ms|丢包|建议|STUN|探测') { $out += $n }
}
Set-Content -Path $logFile -Value ($out -join [Environment]::NewLine) -Encoding UTF8
Write-Output done
