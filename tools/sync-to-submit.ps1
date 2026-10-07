# 开发仓库 → 提审仓库（S:\GitSubmitClass\NetWatch）同步
# 机制：git push（原子、可靠，不会被文件锁坑）；提审仓库配置了
# receive.denyCurrentBranch=updateInstead，推送后其工作区自动更新，
# GitHub Desktop 打开该目录即可看到新提交（必要时 Repository → Refresh）。
# 用法: powershell -ExecutionPolicy Bypass -File tools\sync-to-submit.ps1
$ErrorActionPreference = 'Stop'
$src = Split-Path $PSScriptRoot
$dst = "S:\GitSubmitClass\NetWatch"

Write-Output "开发: $src"
Write-Output "提审: $dst"

# 首次或提审仓库损坏时：重新克隆
if (-not (Test-Path "$dst\.git")) {
    Write-Output "提审仓库不存在，重新克隆…"
    git clone $src $dst
    if ($LASTEXITCODE -ne 0) { throw "克隆失败" }
}

# 接收配置：推送到已检出分支时同步更新工作区
git -C $dst config receive.denyCurrentBranch updateInstead

# 有未提交改动的工作区会拒绝推送（保护审核状态），此处如实报告
$dirty = (git -C $dst status --porcelain | Measure-Object -Line).Lines
if ($dirty -gt 0) {
    Write-Output "⚠ 提审仓库工作区有 $dirty 项未提交改动，本次推送被拒绝。请在 GitHub Desktop 中先处理（提交或放弃）。"
    exit 1
}

git -C $src push submit main
if ($LASTEXITCODE -ne 0) { throw "推送失败（如历史分叉，请检查两侧提交）" }

Write-Output "--- 提审仓库最新提交 ---"
git -C $dst log --oneline -3
Write-Output "完成。GitHub Desktop 中若未立即显示，请 Repository → Refresh。"
