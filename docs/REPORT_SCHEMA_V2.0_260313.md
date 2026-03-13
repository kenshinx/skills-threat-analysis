# QAX Skill Scan — 扫描报告接口文档 v2.0

> **版本**: 2.0 | **更新日期**: 2026-03-13 | **适用对象**: 第三方平台对接

本文档定义 QAX Skill Scan 引擎输出的扫描报告 (`ScanReport`) JSON 格式规范，供第三方系统集成对接使用。

---

## 目录

1. [快速概览](#1-快速概览)
2. [顶层结构: ScanReport](#2-顶层结构-scanreport)
3. [Verdict 裁决对象](#3-verdict-裁决对象)
4. [Finding 发现对象](#4-finding-发现对象)
5. [AnalyzerResult 分析器结果](#5-analyzerresult-分析器结果)
6. [枚举值定义](#6-枚举值定义)
7. [Stats 统计信息](#7-stats-统计信息)
8. [完整 JSON 示例](#8-完整-json-示例)
9. [对接建议](#9-对接建议)
10. [Worker 消息格式 (MQ)](#10-worker-消息格式-mq)
11. [变更记录](#11-变更记录)

---

## 1. 快速概览

```
┌─────────────────────────────────────────────────────┐
│                    ScanReport                       │
│                                                     │
│  scan_id          唯一扫描标识                        │
│  schema_version   "2.0"                             │
│  skill_name       被扫描 Skill 名称                   │
│                                                     │
│  ┌─────────────────────────────────────────────┐    │
│  │  verdict (裁决)                              │    │
│  │  result:  MALICIOUS | SUSPICIOUS | CLEAN     │    │
│  │  action:  BLOCK | REVIEW | ALLOW             │    │
│  │  confidence: 0.0 ~ 1.0                       │    │
│  └─────────────────────────────────────────────┘    │
│                                                     │
│  findings[]       安全发现列表                        │
│  stats            统计摘要                           │
│  analyzer_results 各分析器详情                        │
│  skill_metadata   Skill 元信息                       │
│  scan_config      本次扫描配置                        │
└─────────────────────────────────────────────────────┘
```

**对接方最小关注集**: 只需关注 `verdict.result` + `verdict.recommended_action` 即可做出放行/拦截决策。如需展示详情，再读取 `findings[]`。

---

## 2. 顶层结构: ScanReport

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `schema_version` | string | Y | 报告格式版本，当前为 `"2.0"` |
| `scan_id` | string | Y | 唯一扫描 ID (UUID) |
| `skill_name` | string | Y | Skill 名称 (来自 manifest) |
| `skill_path` | string | Y | 扫描时的文件路径 |
| `scan_timestamp` | string | Y | 扫描时间，ISO 8601 格式，如 `"2026-03-13T10:00:00Z"` |
| `scan_duration_ms` | int | Y | 扫描总耗时 (毫秒) |
| `verdict` | [Verdict](#3-verdict-裁决对象) | Y | 最终裁决 |
| `stats` | [Stats](#7-stats-统计信息) | Y | 统计摘要 |
| `findings` | [Finding[]](#4-finding-发现对象) | Y | 安全发现列表，可为空数组 |
| `analyzer_results` | map\<string, [AnalyzerResult](#5-analyzerresult-分析器结果)\> | Y | 各分析器结果，key 为 analyzer_id |
| `skill_metadata` | object | Y | Skill manifest 元数据 |
| `scan_config` | object | Y | 本次扫描策略配置 |

---

## 3. Verdict 裁决对象

> **这是对接方最核心的字段**，根据 `result` 和 `recommended_action` 做出放行/审核/拦截决策。

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `result` | string | Y | 裁决结果，枚举值见 [VerdictResult](#61-verdictresult-裁决结果) |
| `confidence` | float | Y | 置信度 `[0.0, 1.0]` |
| `level` | string | Y | 最高严重程度，枚举值见 [Severity](#63-severity-严重程度) |
| `summary` | string | Y | 中文裁决摘要 |
| `summary_en` | string | Y | 英文裁决摘要 |
| `key_finding_ids` | string[] | Y | 按严重程度排序的 Top-3 Finding ID |
| `recommended_action` | string | Y | 推荐操作，枚举值见 [RecommendedAction](#62-recommendedaction-推荐操作) |

### 裁决决策矩阵

| result | recommended_action | 对接方建议处理 |
|--------|--------------------|--------------|
| `MALICIOUS` | `BLOCK` | **自动拦截**，禁止安装/使用 |
| `MALICIOUS` | `REVIEW` | 低置信度恶意，转人工审核 |
| `SUSPICIOUS` | `REVIEW` | 存在可疑行为，转人工审核 |
| `CLEAN` | `ALLOW` | 安全，可自动放行 |

### result 判定逻辑

```
优先级从高到低:
1. 威胁情报命中 (ti_score >= 80)                    → MALICIOUS
2. 存在 CRITICAL 级别 findings                       → MALICIOUS
3. 存在 HIGH 或 MEDIUM 级别 findings                 → SUSPICIOUS
4. 仅 LOW/INFO/无 findings                          → CLEAN

注: metadata.meta_false_positive == true 的 findings 不参与裁决
```

### recommended_action 判定逻辑

| 条件 | recommended_action |
|------|-------------------|
| result == `MALICIOUS` AND confidence >= 0.8 | `BLOCK` |
| result == `MALICIOUS` OR result == `SUSPICIOUS` | `REVIEW` |
| 其他 | `ALLOW` |

### confidence 计算规则

**无 findings 时**:
```
confidence = 0.5 + 0.5 × (completed_analyzers / total_analyzers)
```

**有 findings 时**:
```
base = max_severity_weight + ti_bonus(0.15) + diversity_bonus(min(n × 0.05, 0.20))
confidence = min(base, 1.0)
```

| Severity | 权重 (weight) |
|----------|:------------:|
| CRITICAL | 1.0 |
| HIGH | 0.8 |
| MEDIUM | 0.5 |
| LOW | 0.3 |
| INFO | 0.1 |

---

## 4. Finding 发现对象

每个 Finding 代表一个独立的安全发现。

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `id` | string | Y | 确定性 ID，格式: `f_{rule_id}_{8位sha256}`，详见下方生成规则 |
| `rule_id` | string | Y | 触发的规则 ID |
| `analyzer_id` | string | Y | 产生此 finding 的分析器 ID |
| `category` | string | Y | 威胁类别，枚举值见 [ThreatCategory](#64-threatcategory-威胁类别) |
| `severity` | string | Y | 严重程度，枚举值见 [Severity](#63-severity-严重程度) |
| `title` | string | Y | 中文标题 |
| `description` | string | Y | 中文描述 |
| `title_en` | string | Y | 英文标题 |
| `description_en` | string | Y | 英文描述 |
| `location` | [Location](#41-location-对象) | Y | 代码位置信息 |
| `evidence` | [Evidence](#42-evidence-对象) | Y | 匹配证据 |
| `threat_intel` | [ThreatIntelRef](#43-threatintelref-对象) \| null | Y | 威胁情报关联，无则为 null |
| `remediation` | string \| null | N | 修复建议 |
| `metadata` | object | Y | 额外元数据，见 [metadata 特殊字段](#44-findingmetadata-特殊字段) |
| `references` | string[] | Y | 参考链接 (CWE, OWASP 等) |

### Finding.id 生成规则

```python
raw = f"{rule_id}:{file_path}:{line_number}"
hash = sha256(raw.encode("utf-8")).hexdigest()[:8]
id = f"f_{rule_id}_{hash}"
# 示例: "f_COMMAND_INJECTION_EVAL_a1b2c3d4"
```

### 4.1 Location 对象

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `file_path` | string | Y | 文件相对路径 |
| `line_number` | int | Y | 起始行号 (1-based)，0 表示未知 |
| `line_end` | int \| null | N | 结束行号 |
| `column_start` | int \| null | N | 起始列号 |
| `snippet` | string | Y | 匹配到的代码片段 |

### 4.2 Evidence 对象

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `matched_pattern` | string \| null | N | 匹配的正则/规则模式 |
| `matched_content` | string | Y | 实际匹配到的内容 |
| `context_before` | string | N | 匹配位置之前的上下文 |
| `context_after` | string | N | 匹配位置之后的上下文 |

### 4.3 ThreatIntelRef 对象

> 仅当 `analyzer_id == "qax_ti"` 时出现，其他分析器产生的 finding 此字段为 `null`。

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `ioc_type` | string | Y | IOC 类型: `"md5"` / `"sha1"` / `"sha256"` / `"domain"` / `"ip"` / `"url"` |
| `ioc_value` | string | Y | IOC 值 |
| `ti_score` | float | Y | 威胁评分 `[0, 100]` |
| `ti_categories` | string[] | Y | 威胁分类标签 (如 `["trojan", "backdoor"]`) |
| `ti_source` | string | Y | 情报来源，固定为 `"qax_ti"` |

#### TI 评分映射

| 场景 | ti_score | 说明 |
|------|:--------:|------|
| 文件哈希命中 (恶意) | 85.0 | 定向查杀为 100.0 |
| 文件哈希命中 (可疑) | 65.0 | — |
| 网络 IOC - critical | 95.0 | — |
| 网络 IOC - high | 80.0 | — |
| 网络 IOC - medium | 60.0 | — |
| 网络 IOC - low | 40.0 | — |
| 未检出 / 未知 | 0.0 | — |

### 4.4 Finding.metadata 特殊字段

| 字段 | 类型 | 来源分析器 | 说明 |
|------|------|-----------|------|
| `meta_false_positive` | bool | llm_meta | LLM 判定为误报时设为 `true`，**不参与裁决** |
| `original_severity` | string | llm_meta | LLM 调整严重程度前的原始值 |
| `binary_type` | string | binary | 二进制文件类型 (`elf`/`pe`/`macho`/`zip`...) |
| `binary_size` | int | binary | 文件大小 (bytes) |
| `source_taint` | string | pipeline | 污点来源 |
| `sink_taint` | string | pipeline | 污点终点 |
| `taint_chain` | string | pipeline | 完整污点链路 |

---

## 5. AnalyzerResult 分析器结果

按 `analyzer_id` 作为 key 存储在 `analyzer_results` map 中。

| 字段 | 类型 | 必填 | 说明 |
|------|------|:----:|------|
| `analyzer_id` | string | Y | 分析器 ID |
| `status` | string | Y | 执行状态，枚举值见 [AnalyzerStatus](#65-analyzerstatus-分析器状态) |
| `duration_ms` | int | Y | 执行耗时 (毫秒) |
| `findings` | Finding[] | Y | 该分析器产生的 Finding 列表 |
| `verdict` | string | Y | 分析器级别裁决 (VerdictResult 枚举值) |
| `verdict_confidence` | float | Y | 分析器级别置信度 |
| `extra` | object | Y | 分析器特有的扩展数据，见下表 |
| `error` | string \| null | Y | 失败时的错误信息，正常为 null |

### 各分析器 ID 与 extra 字段

| analyzer_id | 名称 | 阶段 | extra 字段 |
|------------|------|:----:|-----------|
| `static` | 静态规则分析 | 1 | `rules_triggered: int`, `files_scanned: int` |
| `bytecode` | 字节码分析 | 1 | `pyc_files_checked: int` |
| `pipeline` | 污点传播分析 | 1 | `files_scanned: int` |
| `behavioral` | 行为模式分析 | 1 | `python_files_analyzed: int` |
| `skill_md` | Skill.md 一致性 | 1 | `alignment_score: float`, `undeclared_tools: list`, `undeclared_domains: list`, `trigger_specificity: str`, `declared_tools: list` |
| `code_quality` | 代码质量分析 | 1 | `quality_score: float`, `issues_by_type: dict` |
| `binary` | 二进制文件分析 | 1 | `binary_hashes: list`, `extracted_iocs: dict`, `binary_files_analyzed: int` |
| `cross_file` | 跨文件分析 | 1 | `python_files_profiled: int`, `cross_file_edges: int` |
| `qax_ti` | 威胁情报查询 | 2 | `iocs_queried: dict`, `iocs_hit: int`, `whitelisted_iocs: int` |
| `llm_semantic` | LLM 语义分析 | 2 | `provider: str`, `total_batches: int`, `batch_errors: int`, `llm_findings_count: int` |
| `llm_meta` | LLM 元审查 | 2 | `provider: str`, `validated_count: int`, `false_positive_count: int`, `severity_adjustments: int` |

---

## 6. 枚举值定义

### 6.1 VerdictResult (裁决结果)

| 枚举值 | 中文 | English | 含义 |
|--------|------|---------|------|
| `MALICIOUS` | 恶意 | Malicious | 确认存在恶意行为或高危威胁情报命中 |
| `SUSPICIOUS` | 可疑 | Suspicious | 存在中高危安全问题，需人工审核 |
| `CLEAN` | 安全 | Clean | 未发现安全问题，或仅有低危/信息性发现 |

### 6.2 RecommendedAction (推荐操作)

| 枚举值 | 中文 | English | 对接方处理建议 |
|--------|------|---------|--------------|
| `BLOCK` | 阻止 | Block | 高置信度恶意，建议**自动拦截**，禁止安装 |
| `REVIEW` | 审核 | Review | 需安全人员**人工审核**后再决定 |
| `ALLOW` | 放行 | Allow | 安全，可**自动放行**使用 |

### 6.3 Severity (严重程度)

| 枚举值 | 权重 | 中文 | English | 裁决影响 |
|--------|:----:|------|---------|---------|
| `CRITICAL` | 1.0 | 严重 | Critical | 触发 → MALICIOUS |
| `HIGH` | 0.8 | 高危 | High | 触发 → SUSPICIOUS |
| `MEDIUM` | 0.5 | 中危 | Medium | 触发 → SUSPICIOUS |
| `LOW` | 0.3 | 低危 | Low | 不影响裁决 → CLEAN |
| `INFO` | 0.1 | 信息 | Info | 不影响裁决 → CLEAN |
| `SAFE` | 0.0 | 安全 | Safe | 安全标记 → CLEAN |

**排序**: `CRITICAL > HIGH > MEDIUM > LOW > INFO > SAFE`

### 6.4 ThreatCategory (威胁类别)

| 枚举值 | 中文 | English | 关联分析器 |
|--------|------|---------|-----------|
| `prompt_injection` | 提示注入 | Prompt Injection | static, code_quality, llm_semantic |
| `command_injection` | 命令注入 | Command Injection | static, behavioral, code_quality, pipeline, cross_file, llm_semantic |
| `data_exfiltration` | 数据外传 | Data Exfiltration | static, behavioral, pipeline, cross_file, llm_semantic |
| `hardcoded_secrets` | 硬编码密钥 | Hardcoded Secrets | static, code_quality, llm_semantic |
| `unauthorized_tool_use` | 未授权工具调用 | Unauthorized Tool Use | static, llm_semantic |
| `obfuscation` | 代码混淆 | Code Obfuscation | static, llm_semantic |
| `social_engineering` | 社会工程 | Social Engineering | static, llm_semantic |
| `resource_abuse` | 资源滥用 | Resource Abuse | static, code_quality, llm_semantic |
| `supply_chain_attack` | 供应链攻击 | Supply Chain Attack | static, llm_semantic |
| `privilege_escalation` | 权限提升 | Privilege Escalation | static, llm_semantic |
| `malicious_guidance` | 恶意引导 | Malicious Guidance | code_quality, llm_semantic |
| `skill_md_mismatch` | Skill.md 不一致 | Skill.md Mismatch | skill_md |
| `code_quality` | 代码质量问题 | Code Quality | code_quality, behavioral |
| `bytecode_tampering` | 字节码篡改 | Bytecode Tampering | bytecode, behavioral |
| `trigger_hijacking` | 触发器劫持 | Trigger Hijacking | skill_md |
| `unicode_steganography` | Unicode 隐写 | Unicode Steganography | static |
| `transitive_trust_abuse` | 传递信任滥用 | Transitive Trust Abuse | cross_file |

### 6.5 AnalyzerStatus (分析器状态)

| 枚举值 | 中文 | English | 说明 |
|--------|------|---------|------|
| `completed` | 完成 | Completed | 正常完成分析 |
| `skipped` | 跳过 | Skipped | 技能包不包含该分析器所需的文件类型 |
| `failed` | 失败 | Failed | 执行过程中出错 |
| `timeout` | 超时 | Timeout | 执行超时 |

### 6.6 ScanPolicy.mode (扫描策略)

| 枚举值 | 中文 | 说明 |
|--------|------|------|
| `strict` | 严格 | 所有规则启用，部分严重程度升级 |
| `balanced` | 平衡 | **默认模式**，禁用低置信度 YARA，每规则最多 5 findings |
| `permissive` | 宽松 | 禁用多条规则，关闭 cross_file，每规则最多 3 findings |

---

## 7. Stats 统计信息

| 字段 | 类型 | 说明 |
|------|------|------|
| `total_findings` | int | 发现总数 |
| `by_severity` | map\<Severity, int\> | 按严重程度统计 |
| `by_category` | map\<ThreatCategory, int\> | 按威胁类别统计 |
| `by_analyzer` | map\<analyzer_id, int\> | 按分析器统计 |

```json
{
  "total_findings": 5,
  "by_severity": { "CRITICAL": 1, "HIGH": 2, "MEDIUM": 1, "LOW": 1, "INFO": 0 },
  "by_category": { "command_injection": 2, "data_exfiltration": 1, "obfuscation": 1, "code_quality": 1 },
  "by_analyzer": { "static": 3, "behavioral": 1, "code_quality": 1 }
}
```

---

## 8. 完整 JSON 示例

```json
{
  "schema_version": "2.0",
  "scan_id": "scan_20260313_100000_a1b2c3d4",
  "skill_name": "example-skill",
  "skill_path": "/tmp/skills/example-skill",
  "scan_timestamp": "2026-03-13T10:00:00.000Z",
  "scan_duration_ms": 4523,

  "verdict": {
    "result": "SUSPICIOUS",
    "confidence": 0.80,
    "level": "HIGH",
    "summary": "检测到可疑行为，共发现 2 个安全问题（HIGHx1，MEDIUMx1），主要威胁类型: command_injection、data_exfiltration。建议人工审查后再决定是否安装。",
    "summary_en": "Suspicious behavior detected, found 2 security issues (HIGHx1, MEDIUMx1), primary threat types: command_injection, data_exfiltration. Manual review recommended before installation.",
    "key_finding_ids": [
      "f_COMMAND_INJECTION_SHELL_TRUE_a1b2c3d4",
      "f_BEHAV_CRED_LEAK_e5f6g7h8"
    ],
    "recommended_action": "REVIEW"
  },

  "stats": {
    "total_findings": 2,
    "by_severity": { "CRITICAL": 0, "HIGH": 1, "MEDIUM": 1, "LOW": 0, "INFO": 0 },
    "by_category": { "command_injection": 1, "data_exfiltration": 1 },
    "by_analyzer": { "static": 1, "behavioral": 1 }
  },

  "findings": [
    {
      "id": "f_COMMAND_INJECTION_SHELL_TRUE_a1b2c3d4",
      "rule_id": "COMMAND_INJECTION_SHELL_TRUE",
      "analyzer_id": "static",
      "category": "command_injection",
      "severity": "HIGH",
      "title": "subprocess 使用 shell=True",
      "description": "subprocess.call() 使用 shell=True 可能导致命令注入",
      "title_en": "subprocess uses shell=True",
      "description_en": "subprocess.call() with shell=True may lead to command injection",
      "location": {
        "file_path": "scripts/run.py",
        "line_number": 15,
        "line_end": null,
        "column_start": null,
        "snippet": "subprocess.call(cmd, shell=True)"
      },
      "evidence": {
        "matched_pattern": "subprocess\\.\\w+\\(.*shell\\s*=\\s*True",
        "matched_content": "subprocess.call(cmd, shell=True)",
        "context_before": "cmd = f'echo {user_input}'",
        "context_after": "print('done')"
      },
      "threat_intel": null,
      "remediation": "使用 subprocess 的列表参数形式，避免 shell=True",
      "metadata": {},
      "references": ["https://cwe.mitre.org/data/definitions/78.html"]
    },
    {
      "id": "f_BEHAV_CRED_LEAK_e5f6g7h8",
      "rule_id": "BEHAV_CRED_LEAK",
      "analyzer_id": "behavioral",
      "category": "data_exfiltration",
      "severity": "MEDIUM",
      "title": "环境变量可能通过网络泄露",
      "description": "os.getenv() 读取的值可能通过 requests.post() 发送到外部",
      "title_en": "Env vars may leak via network",
      "description_en": "Values from os.getenv() may be sent externally via requests.post()",
      "location": {
        "file_path": "scripts/run.py",
        "line_number": 8,
        "line_end": null,
        "column_start": null,
        "snippet": "api_key = os.getenv('API_KEY')"
      },
      "evidence": {
        "matched_pattern": null,
        "matched_content": "os.getenv('API_KEY') ... requests.post()",
        "context_before": "",
        "context_after": ""
      },
      "threat_intel": null,
      "remediation": "确保环境变量不会通过网络请求发送到不受信任的端点",
      "metadata": {},
      "references": []
    }
  ],

  "analyzer_results": {
    "static": {
      "analyzer_id": "static",
      "status": "completed",
      "duration_ms": 120,
      "findings": [],
      "verdict": "SUSPICIOUS",
      "verdict_confidence": 0.75,
      "extra": { "rules_triggered": 1, "files_scanned": 5 },
      "error": null
    },
    "behavioral": {
      "analyzer_id": "behavioral",
      "status": "completed",
      "duration_ms": 85,
      "findings": [],
      "verdict": "SUSPICIOUS",
      "verdict_confidence": 0.40,
      "extra": { "python_files_analyzed": 3 },
      "error": null
    },
    "bytecode": {
      "analyzer_id": "bytecode",
      "status": "skipped",
      "duration_ms": 0,
      "findings": [],
      "verdict": "CLEAN",
      "verdict_confidence": 0.0,
      "extra": {},
      "error": null
    }
  },

  "skill_metadata": {
    "name": "example-skill",
    "description": "An example skill for demonstration",
    "allowed_tools": ["Read", "Write"],
    "trigger_description": "When user asks to process files",
    "author": "dev-team",
    "version": "1.0.0"
  },

  "scan_config": {
    "name": "balanced",
    "mode": "balanced",
    "disabled_rules": [],
    "severity_overrides": {},
    "disabled_analyzers": [],
    "yara_mode": "balanced",
    "max_findings_per_rule": 5,
    "enable_cross_file": true,
    "sensitive_file_patterns": [],
    "known_test_values": [],
    "file_size_limit_kb": 0
  }
}
```

> **注意**: `analyzer_results` 中每个分析器的 `findings` 字段是该分析器产生的 Finding 对象数组。为节省示例篇幅，上方示例中使用空数组代替。实际报告中，顶层 `findings` 是所有分析器 findings 的合集。

---

## 9. 对接建议

### 9.1 最简对接 (仅做放行/拦截)

```python
report = json.loads(scan_result)

action = report["verdict"]["recommended_action"]
if action == "BLOCK":
    reject_skill(report["skill_name"], reason=report["verdict"]["summary"])
elif action == "REVIEW":
    queue_for_review(report["scan_id"], report["verdict"]["summary"])
else:  # ALLOW
    approve_skill(report["skill_name"])
```

### 9.2 展示详情

```python
# 按严重程度排序展示 findings
severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "SAFE"]
findings = sorted(
    report["findings"],
    key=lambda f: severity_order.index(f["severity"])
)

for f in findings:
    print(f"[{f['severity']}] {f['title']} ({f['title_en']})")
    print(f"  文件: {f['location']['file_path']}:{f['location']['line_number']}")
    print(f"  类别: {f['category']}")
    if f.get("remediation"):
        print(f"  修复: {f['remediation']}")
```

### 9.3 版本兼容

- 请始终检查 `schema_version` 字段，确保与本文档版本一致
- 未来版本会保持向后兼容：只新增字段，不删除/修改已有字段
- 如遇到未知字段，请忽略而非报错
- `schema_version` 主版本号变更 (如 2.x → 3.0) 表示不兼容变更

### 9.4 大报告处理 (MongoDB 场景)

当通过 Worker 持久化到 MongoDB 时，大报告会拆分存储:

| 限制 | 阈值 |
|------|------|
| 报告最大体积 | 12 MB |
| 内联 findings 上限 | 500 条 |

超限时 findings 会单独存储，报告中增加字段:
- `findings_ref`: string — 指向 findings 集合的引用 ID
- `findings_stored_separately`: true

---

## 10. Worker 消息格式 (MQ)

### 扫描任务消息 (ScanMessage)

```json
{
  "task_id": "uuid-string",
  "skill_download_url": "https://storage.example.com/skills/my-skill.zip",
  "scan_options": {
    "policy": "balanced",
    "enable_llm": true,
    "enable_qax_ti": true,
    "analyzers": null,
    "disabled_rules": [],
    "severity_overrides": {},
    "llm_provider": ""
  },
  "priority": 5,
  "enqueue_time": "2026-03-13T10:00:00Z"
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `task_id` | string | 唯一任务 ID (UUID) |
| `skill_download_url` | string | Skill 包下载地址 |
| `scan_options.policy` | string | `"strict"` / `"balanced"` / `"permissive"` |
| `scan_options.enable_llm` | bool | 是否启用 LLM 分析 |
| `scan_options.enable_qax_ti` | bool | 是否启用威胁情报查询 |
| `scan_options.analyzers` | string[] \| null | 指定分析器列表，null 为自动规划 |
| `priority` | int | 优先级，数值越小越优先 |
| `enqueue_time` | string | 入队时间 (ISO 8601) |

### 任务生命周期

```
pending → running → completed | failed
```

### MQ 配置

| 配置项 | 值 |
|--------|---|
| queue_name | `skill.scan.queuebatch` |
| prefetch_count | 1 |
| heartbeat | 600s |
| durable | true |

### Skill 下载限制

| 限制 | 值 |
|------|---|
| 最大下载大小 | 200 MB |
| 下载超时 | 120 秒 |

---

## 11. 变更记录

| 版本 | 日期 | 变更内容 |
|------|------|---------|
| 2.0 | 2026-03-13 | 新增 `VerdictResult`、`RecommendedAction`、`AnalyzerStatus` 正式枚举；所有枚举值标准化；新增对接建议章节；文档结构面向三方对接重构 |
| 1.0 | 2026-03-12 | 初始版本 |
