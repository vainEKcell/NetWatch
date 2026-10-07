param([string]$Dir = "S:\ZWorker\NetWatch\verify")
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
$logFile = "S:\ZWorker\NetWatch\verify\uilog.txt"
$netProc = Get-Process NetWatch | Where-Object { $_.MainWindowHandle -ne 0 } | Select-Object -First 1
$root = [System.Windows.Automation.AutomationElement]::RootElement
$cond = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ProcessIdProperty, $netProc.Id)
$win = $root.FindFirst([System.Windows.Automation.TreeScope]::Children, $cond)
$hdrCond = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::DataItem)
$hdrCond2 = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::HeaderItem)
$names = @()
foreach ($ct in @([System.Windows.Automation.ControlType]::HeaderItem, [System.Windows.Automation.ControlType]::Header, [System.Windows.Automation.ControlType]::Text)) {
    $cc = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, $ct)
    $els = $win.FindAll([System.Windows.Automation.TreeScope]::Descendants, $cc)
    foreach ($el in $els) { if ($el.Current.Name -match '累计|速度|进程') { $names += "$($ct.ProgrammaticName): $($el.Current.Name)" } }
}
Set-Content -Path $logFile -Value ($names -join [Environment]::NewLine) -Encoding UTF8
Write-Output done
