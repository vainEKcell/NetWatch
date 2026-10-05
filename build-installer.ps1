# 一键构建安装包：自包含发布（无需目标机装 .NET）→ Inno Setup 打包
# 用法: powershell -ExecutionPolicy Bypass -File build-installer.ps1 [-Version 1.0.0]
param([string]$Version = "1.0.0")
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot

Write-Output '==> 1/3 自包含发布（win-x64，含 .NET 运行时）'
& dotnet publish "$root\src\NetWatch\NetWatch.csproj" -c Release -r win-x64 --self-contained true -o "$root\publish\installer-payload"
if ($LASTEXITCODE -ne 0) { throw "发布失败" }

Write-Output '==> 2/3 定位 Inno Setup（ISCC.exe）'
$iscc = @(
    "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe",
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 6\ISCC.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) { throw "未找到 Inno Setup，请先: winget install JRSoftware.InnoSetup" }
Write-Output "    ISCC: $iscc"

Write-Output '==> 3/3 打包安装器'
& $iscc "/DMyAppVersion=$Version" "$root\setup.iss"
if ($LASTEXITCODE -ne 0) { throw "打包失败" }

$out = "$root\dist\NetWatch-Setup-$Version.exe"
Write-Output "==> 完成: $out ($([math]::Round((Get-Item $out).Length / 1MB, 1)) MB)"
Write-Output '    分发说明：目标机 Windows 10/11 x64 即可，无需任何运行时；安装后首次运行弹 UAC。'
