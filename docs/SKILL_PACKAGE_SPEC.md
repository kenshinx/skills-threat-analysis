# Skill 包格式规范 v1.0

> **版本**: 1.0 | **更新日期**: 2026-03-14 | **适用对象**: Skill 开发者、平台对接方、扫描引擎

本文档定义 Skill 包的目录结构、打包格式及归一化规则，确保扫描引擎能正确解析任意来源的 Skill 包。

---

## 目录

1. [概述](#1-概述)
2. [目录结构](#2-目录结构)
3. [打包格式](#3-打包格式)
4. [归一化规则](#4-归一化规则)
5. [文件路径约定](#5-文件路径约定)
6. [哈希计算中的路径](#6-哈希计算中的路径)
7. [验证与错误处理](#7-验证与错误处理)
8. [FAQ](#8-faq)
9. [变更记录](#9-变更记录)

---

## 1. 概述

Skill 包是一个包含 `SKILL.md` 及相关文件的集合，可以是目录或压缩包 (`.zip` / `.skill`)。扫描引擎需要处理不同来源、不同打包方式的 Skill 包，因此需要统一的归一化规则。

### 核心原则

- **SKILL.md 是 Skill 包的根标识**：`SKILL.md` 所在的目录即为 Skill 的根目录
- **相对路径以 Skill 根目录为基准**：所有文件路径均相对于 Skill 根目录，使用 POSIX 风格 (`/` 分隔)
- **两种打包方式等价**：扫描引擎通过归一化后产生一致的结果

---

## 2. 目录结构

### 2.1 标准目录结构

```
<skill-root>/
├── SKILL.md              # 必需，Skill 描述和 YAML frontmatter
├── _meta.json            # 可选，OpenClaw 元数据
├── LICENSE.txt           # 可选，许可证
├── scripts/              # 可选，脚本目录
│   ├── main.py
│   └── run.sh
├── tests/                # 可选，测试目录
│   └── test_main.py
└── assets/               # 可选，资源文件
    └── config.json
```

### 2.2 必需文件

| 文件 | 说明 |
|------|------|
| `SKILL.md` | Skill 的核心描述文件，包含 YAML frontmatter (name, description, allowed_tools 等) |

### 2.3 常见可选文件

| 文件/目录 | 说明 |
|----------|------|
| `_meta.json` | OpenClaw 平台元数据 (author, version, tags 等) |
| `LICENSE.txt` | 许可证文件 |
| `README.md` | 补充说明文档 |
| `scripts/` | 脚本文件目录 |
| `tests/` | 测试文件目录 |

---

## 3. 打包格式

支持两种打包格式，扫描引擎通过归一化后等价处理。

### 3.1 Flat 格式 (推荐)

`SKILL.md` 直接位于压缩包的根目录下。这是 OpenClaw 平台的 **标准格式**，生产环境中 100% 采用此格式。

```
my-skill.zip (或 .skill)
├── SKILL.md
├── _meta.json
├── scripts/
│   └── main.py
└── run.sh
```

### 3.2 Nested 格式

压缩包内有一个同名的顶层文件夹包裹所有内容，`SKILL.md` 位于该文件夹内。常见于手动压缩或 GitHub 下载的场景。

```
my-skill.zip
└── my-skill/          ← 唯一的顶层目录
    ├── SKILL.md
    ├── _meta.json
    ├── scripts/
    │   └── main.py
    └── run.sh
```

### 3.3 格式对比

| 特性 | Flat 格式 | Nested 格式 |
|------|-----------|-------------|
| 使用场景 | OpenClaw 平台标准打包 | 手动 zip、GitHub archive |
| 生产占比 | **100%** | 0% (但需兼容) |
| `SKILL.md` 位置 | 压缩包根目录 | `<folder>/SKILL.md` |
| 推荐程度 | **推荐** | 兼容支持 |

---

## 4. 归一化规则

扫描引擎在解压后自动归一化，确保两种格式产生一致的结果。

### 4.1 归一化算法

```
1. 解压 ZIP/SKILL 文件到临时目录 tmp_dir
2. 检查 tmp_dir 下的顶层内容:
   - 如果仅有一个顶层目录 (无顶层文件) → root = 该目录 (去掉包裹层)
   - 否则 → root = tmp_dir (已是 flat 格式)
3. 以 root 为基准计算所有 relative_path
```

### 4.2 归一化示例

**Flat 格式输入**:
```
tmp_dir/
├── SKILL.md
├── scripts/main.py
```
→ `root = tmp_dir`
→ `relative_path`: `SKILL.md`, `scripts/main.py`

**Nested 格式输入**:
```
tmp_dir/
└── my-skill/
    ├── SKILL.md
    └── scripts/main.py
```
→ `root = tmp_dir/my-skill/` (自动去掉包裹层)
→ `relative_path`: `SKILL.md`, `scripts/main.py`

### 4.3 归一化后的等价性

归一化后两种格式产生 **完全一致** 的：
- `relative_path` (文件相对路径)
- `file_md5s` / `file_sha1s` 的 key
- `files_md5` / `files_sha1` 组合哈希值
- 所有 Finding 中的 `location.file_path`

> **唯一区别**: `package_md5` / `package_sha1` 不同，因为 ZIP 文件本身的结构不同。

---

## 5. 文件路径约定

### 5.1 relative_path 格式

| 规则 | 说明 |
|------|------|
| 分隔符 | 使用 POSIX `/`，不使用 Windows `\` |
| 起点 | 相对于归一化后的 Skill 根目录 |
| 无前缀 | 不以 `/` 或 `./` 开头 |
| 唯一性 | 同一 Skill 内 relative_path 不重复 |

### 5.2 示例

| 实际路径 | relative_path |
|----------|--------------|
| `<root>/SKILL.md` | `SKILL.md` |
| `<root>/scripts/main.py` | `scripts/main.py` |
| `<root>/lib/utils/helper.py` | `lib/utils/helper.py` |

### 5.3 relative_path 在报告中的使用位置

| 位置 | 字段 |
|------|------|
| `skill_metadata.md5_info.file_md5s` | key |
| `skill_metadata.sha1_info.file_sha1s` | key |
| `skill_metadata.binary_files[]` | 值 |
| `findings[].location.file_path` | 值 |

---

## 6. 哈希计算中的路径

### 6.1 file_md5s / file_sha1s

- key 为归一化后的 `relative_path`
- 不同打包方式解压后，同一文件的 `relative_path` 相同 (归一化保证)
- 因此 `file_md5s` 的内容与打包方式无关

### 6.2 files_md5 / files_sha1 (组合哈希)

组合哈希按 `relative_path` 排序拼接：

```python
parts = [package_md5]                    # 包级哈希 (打包方式不同则不同)
for path in sorted(file_md5s.keys()):    # 按 relative_path 排序
    parts.append(file_md5s[path])
files_md5 = md5("".join(parts))
```

> **注意**: `files_md5` 包含 `package_md5`，因此同一 Skill 用 Flat 和 Nested 方式打包，`files_md5` **会不同** (因为 ZIP 结构不同导致 `package_md5` 不同)。`file_md5s` 中各文件的哈希值则完全相同。

### 6.3 目录加载时

当从目录直接加载 (非压缩包) 时：
- `package_md5` = `""` (空字符串)
- `file_md5s` 正常计算
- `files_md5` = `md5("" + sorted_file_hashes)` — 空字符串参与拼接

---

## 7. 验证与错误处理

### 7.1 加载时验证

| 检查项 | 失败处理 |
|--------|---------|
| 文件存在性 | 抛出 `FileNotFoundError` |
| 文件类型 (目录/ZIP) | 抛出 `ValueError` |
| ZIP 路径穿越 (`../`) | 抛出 `ValueError` |
| ZIP 炸弹 (压缩比) | 抛出 `ValueError` |
| ZIP 大小限制 | 抛出 `ValueError` |

### 7.2 SKILL.md 查找

1. 优先在根目录查找 (大小写不敏感)
2. 若根目录未找到，搜索一级子目录
3. 若仍未找到，`manifest` 使用空默认值，扫描继续

### 7.3 限制

| 限制 | 值 |
|------|---|
| ZIP 最大解压大小 | 200 MB |
| 单文件最大读取大小 | 2 MB |
| 最大压缩比 | 100x |

---

## 8. FAQ

### Q: 为什么推荐 Flat 格式？

Flat 格式没有多余的包裹目录，更简洁。OpenClaw 平台打包时统一使用 Flat 格式。Nested 格式虽然兼容支持，但额外的目录层会增加路径的不一致风险。

### Q: 两种格式打包同一 Skill，哈希值会不同吗？

- `file_md5s` / `file_sha1s` 中的值 **相同** (文件内容不变)
- `file_md5s` 的 key (relative_path) **相同** (归一化保证)
- `package_md5` **不同** (ZIP 文件结构不同)
- `files_md5` **不同** (因为 `package_md5` 参与拼接)

### Q: 如果压缩包内有多个顶层目录，会怎样？

不会触发归一化去包裹，直接以解压目录为 root。例如：

```
bad.zip
├── dir_a/
│   └── SKILL.md
└── dir_b/
    └── extra.py
```

→ `root = tmp_dir` (不去包裹)，`relative_path` 为 `dir_a/SKILL.md`, `dir_b/extra.py`

### Q: .skill 文件和 .zip 文件有区别吗？

没有区别，`.skill` 就是 `.zip` 的重命名。扫描引擎对两者完全等价处理。

---

## 9. 变更记录

| 版本 | 日期 | 变更内容 |
|------|------|---------|
| 1.0 | 2026-03-14 | 初始版本：定义 Flat/Nested 格式、归一化规则、路径约定、哈希计算中的路径影响 |
