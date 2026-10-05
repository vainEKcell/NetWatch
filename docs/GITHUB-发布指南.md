# GitHub 发布指南（NetWatch）

仓库已就绪：干净的提交链、`.gitignore` 齐全（bin/obj/publish/dist/verify 均不入库）、LICENSE 与 README 完备。以下是从零推送到 GitHub 的完整步骤。

## 1. 首次推送

```powershell
cd S:\ZWorker\NetWatch

# 在 github.com 上新建空仓库（不要勾选初始化 README/LICENSE），假设名为 NetWatch
git branch -M main
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
