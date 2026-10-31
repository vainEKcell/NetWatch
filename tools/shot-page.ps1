param([string]$PageName = "DNS 安全", [string]$OutFile = "S:\ZWorker\NetWatch\verify\shot-dns.png")
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName UIAutomationClient
Add-Type -Namespace Win32 -Name Native -MemberDefinition '
[DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
[DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);'
$p = Get-Process NetWatch | Where-Object { $_.MainWindowHandle -ne 0 } | Select-Object -First 1
[Win32.Native]::ShowWindow($p.MainWindowHandle, 9) | Out-Null
[Win32.Native]::SetForegroundWindow($p.MainWindowHandle) | Out-Null
Start-Sleep -Milliseconds 700
$root = [System.Windows.Automation.AutomationElement]::RootElement
$cond = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ProcessIdProperty, $p.Id)
$win = $root.FindFirst([System.Windows.Automation.TreeScope]::Children, $cond)
$c1 = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::NameProperty, $PageName)
$c2 = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::ListItem)
$and = New-Object System.Windows.Automation.AndCondition($c1, $c2)
$nav = $win.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $and)
if ($nav) { ($nav.GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern)).Select(); Start-Sleep -Milliseconds 900 }
$r = $win.Current.BoundingRectangle
$bmp = New-Object System.Drawing.Bitmap([int]$r.Width, [int]$r.Height)
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.CopyFromScreen([int]$r.X, [int]$r.Y, 0, 0, $bmp.Size)
$bmp.Save($OutFile, [System.Drawing.Imaging.ImageFormat]::Png)
Write-Output "saved"
