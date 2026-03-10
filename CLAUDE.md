# Skills Threat Analysis

Prompt Injection scanner for Claude Code skills.

## Project Structure

- `src/scanner/` - Main package
  - `models.py` - Data models (Verdict, Severity, ThreatType, etc.)
  - `loader.py` - File loader that traverses skill directories
  - `orchestrator.py` - Pipeline coordinator for 3-stage scanning
  - `cli.py` - CLI entry point
  - `stage1/engine.py` - Rule-based regex matching engine
  - `stage1/rules.yaml` - Detection rule definitions
  - `stage2/analyzer.py` - LLM semantic analysis via Anthropic API
  - `stage2/prompt_template.md` - Prompt template for LLM analysis
  - `stage3/reporter.py` - Report generator (JSON + Markdown)
- `tests/` - Test suite
- `docs/` - Design documentation

## Development

```bash
poetry install
pytest tests/
```

## Running

```bash
python -m scanner.cli --path ./skills/ --output ./report/
```
