# Skills Threat Analysis

A Claude Code Skill that scans skills from ClawHub, Smithery, skills.sh and other sources for **Prompt Injection** threats.

## Overview

With the rapid growth of community-contributed skills (~100k+), there is an increasing risk of malicious skills embedding prompt injection attacks. This tool automates the detection of such threats through a three-stage scanning pipeline.

### Threat Coverage

| Category | Description |
|----------|-------------|
| Instruction Override | Attempts to make the model ignore system instructions |
| Role Hijacking | Forces the model into an unrestricted persona (e.g. DAN, STAN) |
| System Prompt Manipulation | Overwrites or modifies system-level settings |
| Context Exfiltration | Extracts system prompt or conversation history |
| Steganographic Injection | Hides malicious instructions via zero-width chars, base64, HTML comments |
| Dangerous Operations | Induces file deletion, remote code execution, data exfiltration |
| Social Engineering | Uses authority, urgency, or politeness to bypass safety restrictions |

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
 (regex/kw)    (Claude API)   (JSON + MD)
```

- **Stage 1** — Fast regex-based filtering. Classifies skills as `CLEAN`, `SUSPICIOUS`, or `NEEDS_REVIEW`. Processes 100k files in ~3 minutes.
- **Stage 2** — Semantic analysis via Claude API for `NEEDS_REVIEW` skills. Async batched requests with retry logic.
- **Stage 3** — Aggregates results and generates summary reports in JSON and Markdown.

### False Positive Mitigation

- Code blocks and blockquotes are masked during rule matching
- Educational / defensive skills referencing attack patterns are not flagged
- Low-confidence LLM results are routed to human review instead of auto-classified

## Installation

```bash
pip install -e ".[dev]"
```

## Usage

### As CLI

```bash
# Full scan (Stage 1 + Stage 2 + Report)
python -m scanner.cli --path ./skills/ --output ./report/

# Stage 1 only (fast, no LLM cost)
python -m scanner.cli --path ./skills/ --stage 1

# Custom concurrency and batch size
python -m scanner.cli --path ./skills/ --concurrency 5 --batch-size 10

# Resume an interrupted scan
python -m scanner.cli --resume scan-20260310-143000-abc123
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

## Output

Scan results are written to the output directory:

```
report/
├── summary.json        # Machine-readable scan summary
├── summary.md          # Human-readable report with tables
├── checkpoint.json     # Resume checkpoint (during scan)
└── threats/
    ├── skill-id-1.json # Per-skill threat detail
    └── skill-id-2.json
```

## Project Structure

```
src/scanner/
├── cli.py              # CLI entry point
├── orchestrator.py     # Pipeline coordinator
├── loader.py           # Skill directory loader
├── models.py           # Data models
├── stage1/
│   ├── engine.py       # Regex rule engine
│   └── rules.yaml      # Detection rules (PI-001 ~ PI-007)
├── stage2/
│   ├── analyzer.py     # Async LLM semantic analyzer
│   └── prompt_template.md
└── stage3/
    └── reporter.py     # JSON + Markdown report generator
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
