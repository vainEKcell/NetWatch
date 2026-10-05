# GitHub 发布指南（NetWatch）

仓库已就绪：干净的提交链、`.gitignore` 齐全（bin/obj/publish/dist/verify 均不入库）、LICENSE 与 README 完备。

## 0. 工作流总览（推荐：GitHub Desktop + 提审目录）

- **开发目录**：`S:\ZWorker\NetWatch`（日常在这里改代码、构建、提交）
- **提审目录**：`S:\GitSubmitClass\NetWatch`（完整镜像，含全部 git 历史，专供推送前审核与 GitHub Desktop 推送）
- **同步**：开发完成后运行
  ```powershell
  powershell -ExecutionPolicy Bypass -File S:\ZWorker\NetWatch\tools\sync-to-submit.ps1
  ```
  脚本会把源码与 `.git` 历史镜像过去（自动排除 bin/obj/publish/dist/verify），并输出目标仓库状态。

**首次用 GitHub Desktop 推送：**
1. 打开 GitHub Desktop → `File → Add local repository...` → 选择 `S:\GitSubmitClass\NetWatch`
2. 在 `History` 标签逐个提交审核 diff（这就是推送前的内容审核）
3. 点 `Publish repository` → 起名 `NetWatch` → 按需选择公开/私有 → Publish
4. 以后每次：同步脚本跑完后，Desktop 里 `Fetch origin` → 填提交摘要 → `Commit to main` → `Push origin`

## 1. 命令行方式（可选替代）

```powershell
cd S:\GitSubmitClass\NetWatch

# 在 github.com 上新建空仓库（不要勾选初始化 README/LICENSE），假设名为 NetWatch
git remote add origin https://github.com/<你的用户名>/NetWatch.git
git push -u origin main
```

> 提交身份说明：本仓库的提交作者是 `eastk <eastk@local>`。如需在 GitHub 正确归到你的头像，
> 可在推送前改为 GitHub 昵称 + noreply 邮箱并重写历史（可选）：
> ```powershell
> git config user.name  "<GitHub 用户名>"
> git config user.email "<GitHub 用户名>@users.noreply.github.com"
> git commit --amend --no-edit --reset-author
> ```

## 2. 发布安装包（GitHub Release）

1. 本地构建安装包：`powershell -ExecutionPolicy Bypass -File build-installer.ps1`
   （产出 `dist\NetWatch-Setup-<版本>.exe`，自包含、目标机无需 .NET）
2. 打 Tag 并推送：
   ```powershell
   git tag v1.0.0
   git push origin v1.0.0
   ```
3. 在 GitHub 仓库页 → Releases → Draft a new release → 选择 tag v1.0.0 →
   标题如「NetWatch v1.0.0」→ 拖入 `dist\NetWatch-Setup-1.0.0.exe` → Publish。

命令行方式（装了 GitHub CLI 的话）：
```powershell
gh release create v1.0.0 "dist\NetWatch-Setup-1.0.0.exe" --title "NetWatch v1.0.0" --notes "首个公开版本：每进程流量监控、DNS 劫持三层检测、证据链判定、行为基线。"
```

## 3. 日常迭代

```powershell
git add -A
git commit -m "..."
git push
```

新版本发布：改 `NetWatch.csproj` 的 `<Version>` 与 `build-installer.ps1 -Version x.y.z`，打同名 tag。

## 4. 注意事项

- `dist/`、`publish/` 已在 .gitignore 中，安装包只通过 Release 附件分发，不入 git。
- 仓库内不含任何用户数据；运行期数据全部在用户机的 `%LOCALAPPDATA%\NetWatch`。
- 若仓库设为 public，请确认提交信息与文档中没有你不想公开的内容（当前检查过，仅技术内容）。
