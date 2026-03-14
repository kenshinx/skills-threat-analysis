# Skills Threat Analysis

A prompt injection and malicious behavior scanner for Claude Code skills from ClawHub, Smithery, skills.sh and other sources.

## Overview

With the rapid growth of community-contributed skills (~100k+), there is an increasing risk of malicious skills embedding prompt injection attacks, credential theft, data exfiltration, and other threats. This tool automates the detection of such threats through a three-stage scanning pipeline.

### Threat Categories

| Category | Description | Rules |
|----------|-------------|-------|
| Prompt Injection | Instruction override, role hijacking, system prompt manipulation | PI-001, PI-002, PI-003 |
| Command Injection | Dangerous shell commands, code execution, encoded payload delivery | PI-006 |
| Data Exfiltration | Context/system prompt extraction, network exfiltration, SVG/XSS browser data theft | PI-004, PI-009, PI-017 |
| Hardcoded Secrets | Credential file access, API key exposure, bearer tokens | PI-008 |
| Obfuscation | Zero-width chars, base64 encoding, Unicode steganography | PI-005, PI-011 |
| Social Engineering | Authority/urgency manipulation, trust exploitation, secrecy demands | PI-007 |
| Privilege Escalation | setuid/setgid abuse, sudoers modification, chmod +s | PI-014 |
| Persistence | Crontab, systemctl, LaunchAgent, pm2 persistence mechanisms | PI-013 |
| Filesystem Destruction | rm -rf, shutil.rmtree, fs.unlink patterns | PI-010 |
| Crypto Wallet Access | Wallet file access, seed phrase extraction, web3 key operations | PI-012 |
| Supply Chain Attack | Remote binary download, download-and-execute droppers | PI-016 |
| Trigger Hijacking | Auto-execution demands, exclusivity hijacking of other skills | PI-015 |

### Stage 1 Detection Rules (17 rules)

| Rule ID | Name | Severity | Language |
|---------|------|----------|----------|
| PI-001 | Instruction Override | CRITICAL | EN + ZH |
| PI-002 | Role Hijacking | CRITICAL | EN + ZH |
| PI-003 | System Prompt Manipulation | HIGH | EN + ZH |
| PI-004 | Context Exfiltration | HIGH | EN |
| PI-005 | Steganographic Injection | HIGH | * |
| PI-006 | Dangerous Operation | CRITICAL | EN + ZH |
| PI-007 | Social Engineering Injection | MEDIUM | EN + ZH |
| PI-008 | Credential Access | HIGH | * |
| PI-009 | Network Exfiltration | MEDIUM | * |
| PI-010 | Filesystem Destruction | HIGH | * |
| PI-011 | Obfuscation Standalone | MEDIUM | * |
| PI-012 | Crypto Wallet Access | HIGH | * |
| PI-013 | Persistence Mechanism | HIGH | * |
| PI-014 | Privilege Escalation | HIGH | * |
| PI-015 | Trigger Hijacking | HIGH | EN + ZH |
| PI-016 | Remote Binary Download | CRITICAL | * |
| PI-017 | SVG / HTML XSS | CRITICAL | * |

### Stage 2 LLM Threat Categories

Stage 2 uses LLM semantic analysis to detect 17 threat categories:

`prompt_injection`, `command_injection`, `data_exfiltration`, `hardcoded_secrets`, `unauthorized_tool_use`, `obfuscation`, `social_engineering`, `resource_abuse`, `supply_chain_attack`, `privilege_escalation`, `malicious_guidance`, `skill_md_mismatch`, `code_quality`, `bytecode_tampering`, `trigger_hijacking`, `unicode_steganography`, `transitive_trust_abuse`

## Architecture

```
┌─────────────────────────────────────────────┐
│           /scan-skills (entry)              │
└──────────────────┬──────────────────────────┘
                   ▼
┌─────────────────────────────────────────────┐
│            Orchestrator                     │
└───┬──────────────┬──────────────┬───────────┘
    ▼              ▼              ▼
 Stage 1        Stage 2        Stage 3
 Rule Engine    LLM Analysis   Report Gen
 (14 regex)    (OpenAI API)   (JSON + MD)
```

- **Stage 1** — Fast regex-based filtering with 17 rules (80+ patterns). Classifies skills as `CLEAN` or `SUSPICIOUS`. Supports both English and Chinese patterns.
- **Stage 2** — Semantic analysis via OpenAI-compatible LLM API for `SUSPICIOUS` skills. Async batched requests with retry logic. Detects 17 threat categories.
- **Stage 3** — Generates per-skill threat reports (QAX ScanReport schema v1.0) and batch summary reports in JSON and Markdown.

### Verdict Logic

When Stage 2 LLM analysis is available, its verdict takes priority with one safety guard:

| Stage 2 Verdict | Stage 1 CRITICAL findings | Final Result | Action |
|----------------|--------------------------|-------------|--------|
| MALICIOUS | any | MALICIOUS | BLOCK |
| SUSPICIOUS | any | SUSPICIOUS | REVIEW |
| CLEAN | 0 | CLEAN | ALLOW (Stage 1 findings treated as false positives) |
| CLEAN | ≥ 1 | SUSPICIOUS | REVIEW (LLM may have missed a high-confidence threat) |

When Stage 2 is absent (stage-1-only mode), findings-based logic is used:

| Condition | Result | Action |
|-----------|--------|--------|
| CRITICAL findings >= 1 | SUSPICIOUS | REVIEW |
| HIGH findings >= 1 | SUSPICIOUS | REVIEW |
| MEDIUM findings >= 2 | SUSPICIOUS | REVIEW |
| No findings | CLEAN | ALLOW |

### False Positive Mitigation

- Code blocks and blockquotes are masked during rule matching
- Educational / defensive skills referencing attack patterns are not flagged
- Stage 2 LLM overrides Stage 1 false positives when it determines a skill is benign (for non-CRITICAL findings)
- When Stage 2 says CLEAN but Stage 1 has ≥1 CRITICAL finding, result is downgraded to SUSPICIOUS/REVIEW as a safety guard
- Low-confidence LLM results are routed to human review instead of auto-classified

## Installation

```bash
poetry install
```

## Usage

### As CLI

```bash
# Full scan (Stage 1 + Stage 2 + Report)
python -m scanner.cli --path ./skills/ --output ./report/

# Stage 1 only (fast, no LLM cost)
python -m scanner.cli --path ./skills/ --stage 1

# Stage 2 only (LLM analysis for all skills)
python -m scanner.cli --path ./skills/ --stage 2

# Custom LLM model and API endpoint
python -m scanner.cli --path ./skills/ --model glm-4-plus --api-base https://ark.cn-beijing.volces.com/api/v3

# Custom concurrency and batch size
python -m scanner.cli --path ./skills/ --concurrency 5 --batch-size 10

# Resume an interrupted scan
python -m scanner.cli --resume scan-20260310-143000-abc123

# Verbose debug logging
python -m scanner.cli --path ./skills/ -v
```

### As Claude Code Skill

```
/scan-skills --path ./skills/
```

### CLI Options

| Option | Default | Description |
|--------|---------|-------------|
| `--path` | `./skills` | Directory containing skill files |
| `--output` | `./report` | Report output directory |
| `--stage` | `full` | `1` (rules only), `2` (LLM only), `full` |
| `--severity` | `all` | Minimum severity: `critical`, `high`, `medium`, `all` |
| `--format` | `both` | Output format: `json`, `md`, `both` |
| `--batch-size` | `5` | Skills per LLM batch in Stage 2 |
| `--concurrency` | `3` | Concurrent LLM requests |
| `--resume` | — | Resume a scan by its scan ID |
| `--model` | `glm-4-plus` | LLM model name for Stage 2 |
| `--api-base` | Volcano Engine ARK | OpenAI-compatible API base URL |
| `--api-key-env` | `ARK_API_KEY` | Environment variable name for API key |
| `--log-level` | `INFO` | Logging level: `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `--verbose` / `-v` | — | Shorthand for `--log-level DEBUG` |

## Output

Scan results are written to the output directory:

```
report/
├── summary.json        # Machine-readable scan summary (with skill lists)
├── summary.md          # Human-readable report with tables
├── checkpoint.json     # Resume checkpoint (during scan)
└── threats/
    ├── {skill-name}-{hash}.json  # Per-skill threat detail (QAX ScanReport schema)
    └── ...
```

### Summary Report

`summary.json` includes counts and specific skill file paths for each verdict:

```json
{
  "results": {
    "clean": 21,
    "suspicious": 3,
    "suspicious_skills": ["skills/foo/foo.zip", "..."],
    "malicious": 2,
    "malicious_skills": ["skills/bar/bar.zip", "..."]
  },
  "top_threat_types": [
    {"type": "social_engineering", "count": 5, "skills": ["..."]}
  ]
}
```

## Project Structure

```
src/scanner/
├── cli.py              # CLI entry point
├── orchestrator.py     # Pipeline coordinator
├── loader.py           # Skill directory loader
├── models.py           # Data models (Verdict, ThreatCategory, etc.)
├── stage1/
│   ├── engine.py       # Regex rule engine
│   └── rules.yaml      # Detection rules (PI-001 ~ PI-017)
├── stage2/
│   ├── analyzer.py     # Async LLM semantic analyzer
│   └── prompt_template.md
└── stage3/
    └── reporter.py     # JSON + Markdown report generator (QAX schema)
```

## Development

```bash
# Run tests
pytest tests/ -v

# Run tests with coverage
pytest tests/ -v --cov=scanner
```

## License

MIT
