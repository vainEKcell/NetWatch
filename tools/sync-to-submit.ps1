# 开发目录 → 提审目录（S:\GitSubmitClass\NetWatch）一键同步
# 保留完整 git 历史（含 .git），供 GitHub Desktop 打开审核后推送。
# 用法: powershell -ExecutionPolicy Bypass -File tools\sync-to-submit.ps1
$ErrorActionPreference = 'Stop'

$src = Split-Path $PSScriptRoot                      # 开发根目录（tools 的上一级）
$dst = "S:\GitSubmitClass\NetWatch"                  # 提审目录（项目隔离）

Write-Output "源: $src"
Write-Output "目标: $dst"

# /MIR 镜像（含 .git 历史目录）；排除构建产物与临时内容
robocopy $src $dst /MIR `
    /XD bin obj publish dist verify .vs node_modules `
    /XF *.user *.log `
    /NFL /NDL /NJH /NP /MT:8 | Out-Null

$code = $LASTEXITCODE
if ($code -ge 8) { throw "robocopy 失败，退出码 $code" }

# 同步后校验：目标仓库状态应为干净、历史完整
git -C $dst status --short
$dirty = (git -C $dst status --short | Measure-Object -Line).Lines
$count = (git -C $dst log --oneline | Measure-Object -Line).Lines
Write-Output "同步完成（robocopy 退出码 $code，0-7 均为成功）"
Write-Output "目标仓库：$count 个提交，未提交变更 $dirty 项"
Write-Output "下一步：GitHub Desktop → File → Add local repository → 选择 $dst → 审核历史后 Publish"
