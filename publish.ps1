param([switch]$SelfContained)
# 发布脚本：生成单文件 exe
#   .\publish.ps1                -> 依赖框架版（需要机器上有 .NET 10 运行时，体积小）
#   .\publish.ps1 -SelfContained -> 自包含版（无任何依赖，体积大，可拷贝到别的机器）
$ErrorActionPreference = 'Stop'
$proj = Join-Path $PSScriptRoot 'src\NetWatch\NetWatch.csproj'
$out  = Join-Path $PSScriptRoot 'publish\NetWatch'

$publishArgs = @('publish', $proj, '-c', 'Release', '-r', 'win-x64')
if ($SelfContained) {
    $publishArgs += @('--self-contained', 'true', '/p:EnableCompressionInSingleFile=true')
    Write-Output '==> 发布模式：自包含单文件（约 100+ MB）'
} else {
    $publishArgs += @('--self-contained', 'false')
    Write-Output '==> 发布模式：依赖框架单文件（需 .NET 10 桌面运行时）'
}
$publishArgs += @('/p:PublishSingleFile=true', '/p:IncludeNativeLibrariesForSelfExtract=true', '-o', $out)

& dotnet @publishArgs
if ($LASTEXITCODE -ne 0) { throw "发布失败" }
Write-Output "==> 完成。输出目录: $out"
Write-Output '==> 运行 NetWatch.exe 时会请求管理员权限（ETW 内核跟踪与防火墙规则所需）。'
