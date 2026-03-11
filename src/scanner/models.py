"""Data models for the prompt injection scanner."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Verdict(Enum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    NEEDS_REVIEW = "needs_review"
    MALICIOUS = "malicious"
    BENIGN = "benign"
    ERROR = "error"


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ThreatType(Enum):
    INSTRUCTION_OVERRIDE = "instruction_override"
    ROLE_HIJACKING = "role_hijacking"
    SYSTEM_PROMPT_MANIPULATION = "system_prompt_manipulation"
    CONTEXT_EXFILTRATION = "context_exfiltration"
    STEGANOGRAPHIC_INJECTION = "steganographic_injection"
    DANGEROUS_OPERATION = "dangerous_operation"
    SOCIAL_ENGINEERING = "social_engineering"


@dataclass
class SkillFile:
    id: str
    source: str
    file_path: str
    content: str
    size_bytes: int


@dataclass
class RuleMatch:
    rule_id: str
    rule_name: str
    severity: Severity
    matched_text: str
    position: tuple[int, int]


@dataclass
class Threat:
    type: ThreatType
    severity: Severity
    evidence: str
    explanation: str


@dataclass
class Stage1Result:
    verdict: Verdict
    matched_rules: list[RuleMatch] = field(default_factory=list)
    duration_ms: int = 0


@dataclass
class Stage2Result:
    verdict: Verdict
    confidence: float = 0.0
    threats: list[Threat] = field(default_factory=list)
    summary: str = ""
    duration_ms: int = 0


@dataclass
class ScanResult:
    skill: SkillFile
    stage1: Optional[Stage1Result] = None
    stage2: Optional[Stage2Result] = None
    final_verdict: Verdict = Verdict.CLEAN


@dataclass
class ScanSummary:
    scan_id: str
    timestamp: str
    total_scanned: int = 0
    clean: int = 0
    suspicious: int = 0
    malicious: int = 0
    needs_human_review: int = 0
    scan_error: int = 0
    threat_type_counts: dict[str, int] = field(default_factory=dict)
    source_breakdown: dict[str, dict] = field(default_factory=dict)
