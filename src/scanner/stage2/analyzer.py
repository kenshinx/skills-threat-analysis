"""Stage 2: LLM-based semantic analysis for prompt injection detection."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from pathlib import Path
from string import Template
from typing import Any

import openai

from scanner.models import (
    RuleMatch,
    Severity,
    Stage2Result,
    Threat,
    ThreatType,
    Verdict,
)

logger = logging.getLogger(__name__)

# Patterns indicating the LLM refused to answer (content safety filter).
_REFUSAL_PATTERNS = [
    "抱歉", "无法回答", "无法提供", "未找到相关结果",
    "我不能", "不适合回答", "无法处理",
    "i can't", "i cannot", "i'm unable", "i am unable",
    "against my guidelines",
]


class LLMRefusalError(Exception):
    """Raised when the LLM refuses to analyze content."""
    pass


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
# Max number of matched rules to include in LLM prompt.
_MAX_RULES_IN_PROMPT = 30

# Default: Volcano Engine ARK API
_DEFAULT_API_BASE = "https://ark.cn-beijing.volces.com/api/v3"
_DEFAULT_MODEL = "glm-4-plus"


class SemanticAnalyzer:
    def __init__(
        self,
        model: str | None = None,
        api_key: str | None = None,
        api_base: str | None = None,
        max_retries: int = 3,
        concurrency: int = 3,
        batch_size: int = 5,
    ):
        self._model = model or _DEFAULT_MODEL
        self._client = openai.AsyncOpenAI(
            api_key=api_key or "required-but-set-via-env",
            base_url=api_base or _DEFAULT_API_BASE,
        )
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
                    parsed = self._parse_response(result, elapsed_ms)
                    threat_summary = ", ".join(t.type.value for t in parsed.threats) if parsed.threats else "none"
                    logger.debug(
                        "Skill %s: verdict=%s confidence=%.2f threats=[%s] (%dms)",
                        skill_id, parsed.verdict.value, parsed.confidence,
                        threat_summary, elapsed_ms,
                    )
                    return parsed
                except LLMRefusalError as e:
                    elapsed_ms = int((time.monotonic() - start) * 1000)
                    logger.warning(
                        "Skill %s: LLM refused to analyze (content safety filter): %s",
                        skill_id, e,
                    )
                    logger.debug(
                        "Skill %s: verdict=error (LLM refusal) (%dms)",
                        skill_id, elapsed_ms,
                    )
                    return Stage2Result(
                        verdict=Verdict.ERROR,
                        summary="LLM refused to analyze — content triggered safety filter",
                        duration_ms=elapsed_ms,
                    )
                except (json.JSONDecodeError, KeyError, ValueError) as e:
                    logger.warning(
                        "Skill %s: parse error on attempt %d/%d: %s",
                        skill_id, attempt, self._max_retries, e,
                    )
                except openai.APIStatusError as e:
                    logger.warning(
                        "Skill %s: API status error on attempt %d/%d: %s (status=%s)",
                        skill_id, attempt, self._max_retries, e.message,
                        e.status_code,
                    )
                    # Don't retry on 400 (bad request / input too long)
                    if e.status_code == 400:
                        break
                    if attempt < self._max_retries:
                        await asyncio.sleep(2 ** attempt)
                except openai.APIConnectionError as e:
                    logger.warning(
                        "Skill %s: API connection error on attempt %d/%d: %s",
                        skill_id, attempt, self._max_retries, e,
                    )
                    if attempt < self._max_retries:
                        await asyncio.sleep(2 ** attempt)
                except openai.AuthenticationError as e:
                    logger.error(
                        "Skill %s: authentication failed: %s", skill_id, e)
                    break
                except Exception as e:
                    logger.error(
                        "Skill %s: unexpected error on attempt %d/%d: %s: %s",
                        skill_id, attempt, self._max_retries,
                        type(e).__name__, e,
                    )
                    if attempt < self._max_retries:
                        await asyncio.sleep(2 ** attempt)

        elapsed_ms = int((time.monotonic() - start) * 1000)
        logger.debug(
            "Skill %s: verdict=error (all retries exhausted) (%dms)",
            skill_id, elapsed_ms,
        )
        return Stage2Result(
            verdict=Verdict.ERROR, summary="Analysis failed after retries",
            duration_ms=elapsed_ms,
        )

    def _build_prompt(self, content: str, matched_rules: list[RuleMatch]) -> str:
        escaped = content[:_MAX_CONTENT_LENGTH]

        if not matched_rules:
            rules_desc = "None"
        else:
            # Deduplicate rules: keep one example per (rule_id, rule_name) pair
            seen: dict[str, RuleMatch] = {}
            for m in matched_rules:
                if m.rule_id not in seen:
                    seen[m.rule_id] = m
            deduped = list(seen.values())[:_MAX_RULES_IN_PROMPT]
            lines = [
                f"- [{m.rule_id}] {m.rule_name} ({m.severity.value}): "
                f"matched \"{m.matched_text[:100]}\""
                for m in deduped
            ]
            if len(matched_rules) > len(deduped):
                lines.append(
                    f"- ... and {len(matched_rules) - len(deduped)} more matches omitted"
                )
            rules_desc = "\n".join(lines)

        return self._prompt_template.safe_substitute(
            skill_content=escaped,
            matched_rules=rules_desc,
        )

    async def _call_llm(self, prompt: str) -> dict[str, Any]:
        response = await self._client.chat.completions.create(
            model=self._model,
            max_tokens=4096,
            messages=[{"role": "user", "content": prompt}],
        )
        raw = response.choices[0].message.content
        if not raw or not raw.strip():
            raise ValueError("LLM returned empty response")
        text = raw.strip()
        # Detect LLM refusal before attempting JSON parse
        text_lower = text.lower()
        if not text_lower.startswith("{") and any(p in text_lower for p in _REFUSAL_PATTERNS):
            raise LLMRefusalError(f"LLM refused to analyze: {text[:200]}")
        return self._extract_json(text)

    @staticmethod
    def _extract_json(text: str) -> dict[str, Any]:
        """Extract JSON from LLM response, handling various formats."""
        import re

        # Try direct parse first
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Extract from markdown code block (```json ... ``` or ``` ... ```)
        code_block = re.search(r"```(?:json)?\s*\n(.*?)```", text, re.DOTALL)
        if code_block:
            try:
                return json.loads(code_block.group(1).strip())
            except json.JSONDecodeError:
                pass

        # Extract first JSON object by finding balanced braces
        brace_start = text.find("{")
        if brace_start != -1:
            depth = 0
            for i in range(brace_start, len(text)):
                if text[i] == "{":
                    depth += 1
                elif text[i] == "}":
                    depth -= 1
                    if depth == 0:
                        try:
                            return json.loads(text[brace_start:i + 1])
                        except json.JSONDecodeError:
                            break

        raise json.JSONDecodeError(
            f"No valid JSON found in LLM response: {text[:200]}...",
            text, 0,
        )

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
