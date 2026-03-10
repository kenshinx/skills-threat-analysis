"""Stage 2: LLM-based semantic analysis for prompt injection detection."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from pathlib import Path
from string import Template
from typing import Any

import anthropic

from scanner.models import (
    RuleMatch,
    Severity,
    Stage2Result,
    Threat,
    ThreatType,
    Verdict,
)

logger = logging.getLogger(__name__)

_PROMPT_TEMPLATE_PATH = Path(__file__).parent / "prompt_template.md"
_THREAT_TYPE_MAP = {
    "instruction_override": ThreatType.INSTRUCTION_OVERRIDE,
    "role_hijacking": ThreatType.ROLE_HIJACKING,
    "context_exfiltration": ThreatType.CONTEXT_EXFILTRATION,
    "steganographic_injection": ThreatType.STEGANOGRAPHIC_INJECTION,
    "dangerous_operation": ThreatType.DANGEROUS_OPERATION,
    "social_engineering": ThreatType.SOCIAL_ENGINEERING,
    "system_prompt_manipulation": ThreatType.SYSTEM_PROMPT_MANIPULATION,
}
_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}

# Max content length to send to LLM (chars). Truncate longer skills.
_MAX_CONTENT_LENGTH = 12000


class SemanticAnalyzer:
    def __init__(
        self,
        model: str = "claude-sonnet-4-20250514",
        max_retries: int = 3,
        concurrency: int = 3,
        batch_size: int = 5,
    ):
        self._client = anthropic.AsyncAnthropic()
        self._model = model
        self._max_retries = max_retries
        self._semaphore = asyncio.Semaphore(concurrency)
        self._batch_size = batch_size
        self._prompt_template = Template(_PROMPT_TEMPLATE_PATH.read_text(encoding="utf-8"))

    async def analyze_batch(
        self, items: list[tuple[str, str, list[RuleMatch]]]
    ) -> list[Stage2Result]:
        """Analyze a batch of skills concurrently.

        Args:
            items: list of (skill_id, content, matched_rules) tuples.

        Returns:
            list of Stage2Result in the same order.
        """
        tasks = [
            self._analyze_one(skill_id, content, matched_rules)
            for skill_id, content, matched_rules in items
        ]
        return await asyncio.gather(*tasks)

    async def _analyze_one(
        self, skill_id: str, content: str, matched_rules: list[RuleMatch]
    ) -> Stage2Result:
        start = time.monotonic()
        async with self._semaphore:
            prompt = self._build_prompt(content, matched_rules)
            for attempt in range(1, self._max_retries + 1):
                try:
                    result = await self._call_llm(prompt)
                    elapsed_ms = int((time.monotonic() - start) * 1000)
                    return self._parse_response(result, elapsed_ms)
                except (json.JSONDecodeError, KeyError, ValueError) as e:
                    logger.warning(
                        "Skill %s: parse error on attempt %d/%d: %s",
                        skill_id, attempt, self._max_retries, e,
                    )
                except anthropic.APIError as e:
                    logger.warning(
                        "Skill %s: API error on attempt %d/%d: %s",
                        skill_id, attempt, self._max_retries, e,
                    )
                    if attempt < self._max_retries:
                        await asyncio.sleep(2 ** attempt)
                except TypeError as e:
                    # Auth errors (missing API key) raise TypeError, no point retrying
                    logger.error("Skill %s: auth/config error: %s", skill_id, e)
                    break

        elapsed_ms = int((time.monotonic() - start) * 1000)
        return Stage2Result(
            verdict=Verdict.ERROR, summary="Analysis failed after retries",
            duration_ms=elapsed_ms,
        )

    def _build_prompt(self, content: str, matched_rules: list[RuleMatch]) -> str:
        # Escape skill content to prevent the analysis itself from being injected
        escaped = content[:_MAX_CONTENT_LENGTH]

        rules_desc = "None" if not matched_rules else "\n".join(
            f"- [{m.rule_id}] {m.rule_name} ({m.severity.value}): matched \"{m.matched_text}\""
            for m in matched_rules
        )
        return self._prompt_template.safe_substitute(
            skill_content=escaped,
            matched_rules=rules_desc,
        )

    async def _call_llm(self, prompt: str) -> dict[str, Any]:
        response = await self._client.messages.create(
            model=self._model,
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}],
        )
        text = response.content[0].text.strip()
        # Extract JSON from possible markdown code block
        if text.startswith("```"):
            lines = text.split("\n")
            # Remove first and last lines (``` markers)
            json_lines = []
            in_block = False
            for line in lines:
                if line.strip().startswith("```") and not in_block:
                    in_block = True
                    continue
                if line.strip() == "```" and in_block:
                    break
                if in_block:
                    json_lines.append(line)
            text = "\n".join(json_lines)
        return json.loads(text)

    @staticmethod
    def _parse_response(data: dict[str, Any], elapsed_ms: int) -> Stage2Result:
        verdict_str = data["verdict"].upper()
        verdict_map = {
            "MALICIOUS": Verdict.MALICIOUS,
            "SUSPICIOUS": Verdict.SUSPICIOUS,
            "BENIGN": Verdict.BENIGN,
        }
        verdict = verdict_map.get(verdict_str, Verdict.NEEDS_REVIEW)

        threats = []
        for t in data.get("threats", []):
            threat_type = _THREAT_TYPE_MAP.get(t.get("type", ""))
            severity = _SEVERITY_MAP.get(t.get("severity", "").upper())
            if threat_type and severity:
                threats.append(Threat(
                    type=threat_type,
                    severity=severity,
                    evidence=t.get("evidence", ""),
                    explanation=t.get("explanation", ""),
                ))

        return Stage2Result(
            verdict=verdict,
            confidence=float(data.get("confidence", 0.0)),
            threats=threats,
            summary=data.get("summary", ""),
            duration_ms=elapsed_ms,
        )
