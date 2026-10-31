param()
Add-Type -AssemblyName UIAutomationClient
$p = Get-Process NetWatch | Where-Object { $_.MainWindowHandle -ne 0 } | Select-Object -First 1
$root = [System.Windows.Automation.AutomationElement]::RootElement
$cond = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ProcessIdProperty, $p.Id)
$win = $root.FindFirst([System.Windows.Automation.TreeScope]::Children, $cond)
$tc = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Text)
$els = $win.FindAll([System.Windows.Automation.TreeScope]::Descendants, $tc)
$out = @()
foreach ($el in $els) {
    $n = $el.Current.Name
    if ($n -match 'Mapping|外部地址|公网|RFC|对称|锥形|场景|无法检测|数据不足|直连|NAT') { $out += $n }
}
Set-Content -Path "S:\ZWorker\NetWatch\verify\nat-text.txt" -Value ($out -join [Environment]::NewLine) -Encoding UTF8
Write-Output done
