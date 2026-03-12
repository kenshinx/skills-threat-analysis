"""Stage 1: Rule-based fast filtering engine."""

from __future__ import annotations

import re
import time
from pathlib import Path

import yaml

from scanner.models import RuleMatch, Severity, Stage1Result, Verdict

_RULES_PATH = Path(__file__).parent / "rules.yaml"

# Regex to detect if matched text is inside a markdown code block or blockquote
_CODE_BLOCK_RE = re.compile(r"```[\s\S]*?```|`[^`]+`", re.MULTILINE)
_BLOCKQUOTE_RE = re.compile(r"^>.*$", re.MULTILINE)

# Emoji ranges used to detect ZWJ sequences (U+200D between emoji codepoints)
_EMOJI_RANGE_RE = re.compile(
    "[\U0001F300-\U0001FAFF\U00002600-\U000027BF\U0001F900-\U0001F9FF]"
)


class RuleEngine:
    def __init__(self, rules_path: str | Path | None = None):
        path = Path(rules_path) if rules_path else _RULES_PATH
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        self._rules = data["rules"]
        self._compiled: list[dict] = []
        for rule in self._rules:
            compiled_patterns = []
            for pat in rule["patterns"]:
                compiled_patterns.append(re.compile(pat, re.IGNORECASE))
            self._compiled.append({
                "id": rule["id"],
                "name": rule["name"],
                "severity": Severity(rule["severity"].lower()),
                "patterns": compiled_patterns,
            })

    def scan(self, content: str) -> Stage1Result:
        start = time.monotonic()
        matches: list[RuleMatch] = []
        masked_ranges = self._get_masked_ranges(content)

        for rule in self._compiled:
            for pattern in rule["patterns"]:
                for m in pattern.finditer(content):
                    if self._is_in_masked_range(m.start(), m.end(), masked_ranges):
                        continue
                    # Skip U+200D (ZWJ) when it's part of an emoji sequence
                    if m.group() == "\u200d" and self._is_emoji_zwj(content, m.start()):
                        continue
                    matches.append(RuleMatch(
                        rule_id=rule["id"],
                        rule_name=rule["name"],
                        severity=rule["severity"],
                        matched_text=m.group(),
                        position=(m.start(), m.end()),
                        pattern=pattern.pattern,
                    ))

        verdict = self._classify(matches)
        elapsed_ms = int((time.monotonic() - start) * 1000)
        return Stage1Result(verdict=verdict, matched_rules=matches, duration_ms=elapsed_ms)

    def _get_masked_ranges(self, content: str) -> list[tuple[int, int]]:
        """Find ranges of code blocks and blockquotes to reduce false positives."""
        ranges = []
        for m in _CODE_BLOCK_RE.finditer(content):
            ranges.append((m.start(), m.end()))
        for m in _BLOCKQUOTE_RE.finditer(content):
            ranges.append((m.start(), m.end()))
        return ranges

    @staticmethod
    def _is_in_masked_range(start: int, end: int, ranges: list[tuple[int, int]]) -> bool:
        for r_start, r_end in ranges:
            if start >= r_start and end <= r_end:
                return True
        return False

    @staticmethod
    def _is_emoji_zwj(content: str, pos: int) -> bool:
        """Check if U+200D at pos is a ZWJ joiner between emoji characters."""
        def _is_emoji_char(ch: str) -> bool:
            return bool(_EMOJI_RANGE_RE.match(ch))

        before = content[pos - 1] if pos > 0 else ""
        after = content[pos + 1] if pos + 1 < len(content) else ""
        return _is_emoji_char(before) or _is_emoji_char(after)

    @staticmethod
    def _classify(matches: list[RuleMatch]) -> Verdict:
        critical = sum(1 for m in matches if m.severity == Severity.CRITICAL)
        high = sum(1 for m in matches if m.severity == Severity.HIGH)
        medium = sum(1 for m in matches if m.severity == Severity.MEDIUM)

        if critical >= 1:
            return Verdict.SUSPICIOUS
        if high >= 2:
            return Verdict.SUSPICIOUS
        if high == 1:
            return Verdict.NEEDS_REVIEW
        if medium >= 2:
            return Verdict.NEEDS_REVIEW
        return Verdict.CLEAN
