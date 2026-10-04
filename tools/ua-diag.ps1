param([string]$Dir = "S:\ZWorker\NetWatch\verify")
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName UIAutomationClient
New-Item -ItemType Directory -Force -Path $Dir | Out-Null

$lines = @()
$pids = (Get-Process NetWatch -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id)
$lines += "NetWatch PIDs: $($pids -join ', ')"

$root = [System.Windows.Automation.AutomationElement]::RootElement
$kids = $root.FindAll([System.Windows.Automation.TreeScope]::Children, [System.Windows.Automation.Condition]::TrueCondition)
$lines += "Root children: $($kids.Count)"
foreach ($k in $kids) {
    $lines += ("{0}`t{1}" -f $k.Current.ProcessId, $k.Current.Name)
}
Set-Content -Path (Join-Path $Dir 'uatree.txt') -Value ($lines -join [Environment]::NewLine) -Encoding UTF8
Write-Output "diag written"
