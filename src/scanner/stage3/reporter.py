"""Stage 3: Result aggregation and report generation.

Outputs per-skill reports conforming to the QAX ScanReport schema v1.0,
covering only the `static` (Stage 1) and `llm_semantic` (Stage 2) analyzers.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scanner.models import (
    AnalyzerStatus,
    RecommendedAction,
    ScanResult,
    ScanSummary,
    Severity,
    Verdict,
)

# Map rule_name → ThreatCategory value for static findings.
# Falls back to rule_name itself if not found.
_RULE_CATEGORY_MAP = {
    # PI-001~007 (original rules)
    "instruction_override": "prompt_injection",
    "role_hijacking": "prompt_injection",
    "system_prompt_manipulation": "prompt_injection",
    "context_exfiltration": "data_exfiltration",
    "steganographic_injection": "unicode_steganography",
    "dangerous_operation": "command_injection",
    "social_engineering_injection": "social_engineering",
    # PI-008~014 (from skill-scan-1.0.0)
    "credential_access": "hardcoded_secrets",
    "network_exfiltration": "data_exfiltration",
    "filesystem_destruction": "command_injection",
    "obfuscation_standalone": "obfuscation",
    "crypto_wallet_access": "data_exfiltration",
    "persistence_mechanism": "command_injection",
    "privilege_escalation": "privilege_escalation",
    # PA-001~006 (advanced analyzer)
    "invisible_unicode_density": "unicode_steganography",
    "invisible_unicode_hidden_injection": "unicode_steganography",
    "homoglyph_attack": "unicode_steganography",
    "mixed_scripts_latin_cyrillic": "unicode_steganography",
    "mixed_scripts_multi": "unicode_steganography",
    "markdown_hidden_instruction": "prompt_injection",
    "markdown_data_uri": "obfuscation",
    "gradual_escalation": "social_engineering",
    "encoded_payload_base64": "obfuscation",
    "encoded_payload_rot13": "obfuscation",
    # PI-015~017
    "trigger_hijacking": "trigger_hijacking",
    "remote_binary_download": "supply_chain_attack",
    "svg_html_xss": "data_exfiltration",
}

# Map ThreatCategory value → ThreatCategory value for LLM findings.
_THREAT_CATEGORY_MAP = {
    "instruction_override": "prompt_injection",
    "role_hijacking": "prompt_injection",
    "system_prompt_manipulation": "prompt_injection",
    "context_exfiltration": "data_exfiltration",
    "steganographic_injection": "unicode_steganography",
    "dangerous_operation": "command_injection",
    "social_engineering": "social_engineering",
    # Direct category names (LLM may return these directly)
    "prompt_injection": "prompt_injection",
    "command_injection": "command_injection",
    "data_exfiltration": "data_exfiltration",
    "hardcoded_secrets": "hardcoded_secrets",
    "obfuscation": "obfuscation",
    "privilege_escalation": "privilege_escalation",
    "unicode_steganography": "unicode_steganography",
}

# Severity string used in the schema (uppercase).
_SEVERITY_LABEL = {
    Severity.CRITICAL: "CRITICAL",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MEDIUM",
    Severity.LOW: "LOW",
    Severity.INFO: "INFO",
    Severity.SAFE: "SAFE",
}

# Severity ordering for sorting (higher = more severe).
_SEVERITY_ORDER = {
    Severity.CRITICAL: 6,
    Severity.HIGH: 5,
    Severity.MEDIUM: 4,
    Severity.LOW: 3,
    Severity.INFO: 2,
    Severity.SAFE: 1,
}


def _make_finding_id(rule_id: str, file_path: str, line_number: int) -> str:
    """Generate deterministic finding ID: f_{rule_id}_{8-char hash}."""
    raw = f"{rule_id}:{file_path}:{line_number}"
    h = hashlib.sha256(raw.encode()).hexdigest()[:8]
    return f"f_{rule_id}_{h}"


def _offset_to_line(content: str, offset: int) -> int:
    """Convert a character offset to a 1-based line number."""
    return content[:offset].count("\n") + 1


def _get_context(content: str, start: int, end: int, lines: int = 2) -> tuple[str, str]:  # noqa: ARG001
    """Extract context_before and context_after around [start, end)."""
    all_lines = content.splitlines(keepends=True)
    line_no = content[:start].count("\n")  # 0-based

    # context_before: up to `lines` lines before the match line
    before_start = max(0, line_no - lines)
    before = "".join(all_lines[before_start:line_no]).rstrip("\n")

    # context_after: up to `lines` lines after the match line
    after_start = line_no + 1
    after_end = min(len(all_lines), after_start + lines)
    after = "".join(all_lines[after_start:after_end]).rstrip("\n")

    return before, after


def _get_snippet(content: str, start: int, end: int) -> str:
    """Get the full line containing the match as snippet."""
    line_start = content.rfind("\n", 0, start) + 1
    line_end = content.find("\n", end)
    if line_end == -1:
        line_end = len(content)
    return content[line_start:line_end].strip()


class Reporter:
    def __init__(self, output_dir: str | Path):
        self._output_dir = Path(output_dir)
        self._threats_dir = self._output_dir / "threats"
        self._threats_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, scan_id: str, results: list[ScanResult]) -> ScanSummary:
        summary = self._build_summary(scan_id, results)
        self._write_threat_reports(results, scan_id)
        self._write_summary_json(summary)
        self._write_summary_md(summary, results)
        return summary

    # ------------------------------------------------------------------ #
    #  Per-skill report (QAX ScanReport schema v1.0)
    # ------------------------------------------------------------------ #

    def _write_threat_reports(self, results: list[ScanResult], scan_id: str) -> None:
        for r in results:
            # Output report if ANY stage detected issues:
            has_stage1_findings = bool(
                r.stage1 and r.stage1.matched_rules)
            has_stage2_findings = bool(
                r.stage2 and r.stage2.threats)
            has_non_clean_verdict = r.final_verdict in (
                Verdict.MALICIOUS, Verdict.SUSPICIOUS)

            if has_non_clean_verdict or has_stage1_findings or has_stage2_findings:
                report = self._build_skill_report(r, scan_id)
                path = self._threats_dir / f"{r.skill.id}.json"
                path.write_text(
                    json.dumps(report, ensure_ascii=False, indent=2),
                    encoding="utf-8",
                )

    def _build_skill_report(self, r: ScanResult, scan_id: str) -> dict[str, Any]:
        """Build a single-skill report conforming to the QAX schema."""
        now = datetime.now(timezone.utc)
        content = r.skill.content

        # Build findings from both stages
        findings: list[dict[str, Any]] = []

        # --- Static findings (Stage 1) ---
        if r.stage1 and r.stage1.matched_rules:
            for m in r.stage1.matched_rules:
                line_no = _offset_to_line(content, m.position[0])
                snippet = _get_snippet(content, m.position[0], m.position[1])
                ctx_before, ctx_after = _get_context(
                    content, m.position[0], m.position[1])
                category = _RULE_CATEGORY_MAP.get(m.rule_name, m.rule_name)
                fid = _make_finding_id(m.rule_id, r.skill.file_path, line_no)

                findings.append({
                    "id": fid,
                    "rule_id": m.rule_id,
                    "analyzer_id": "static",
                    "category": category,
                    "severity": _SEVERITY_LABEL[m.severity],
                    "title": f"规则匹配: {m.rule_id} ({m.rule_name})",
                    "description": f"检测到 {m.rule_name} 类型的可疑模式",
                    "title_en": f"Rule Match: {m.rule_id} ({m.rule_name})",
                    "description_en": f"Detected suspicious pattern of type {m.rule_name}",
                    "location": {
                        "file_path": r.skill.file_path,
                        "line_number": line_no,
                        "line_end": None,
                        "column_start": None,
                        "snippet": snippet[:500],
                    },
                    "evidence": {
                        "matched_pattern": m.pattern,
                        "matched_content": m.matched_text[:500],
                        "context_before": ctx_before[:500],
                        "context_after": ctx_after[:500],
                    },
                    "threat_intel": None,
                    "remediation": None,
                    "metadata": {},
                    "references": [],
                })

        # --- LLM Semantic findings (Stage 2) ---
        if r.stage2 and r.stage2.threats:
            for t in r.stage2.threats:
                rule_id = f"LLM_{t.category.value.upper()}"
                category = _THREAT_CATEGORY_MAP.get(
                    t.category.value, t.category.value)
                fid = _make_finding_id(rule_id, r.skill.file_path, 0)

                findings.append({
                    "id": fid,
                    "rule_id": rule_id,
                    "analyzer_id": "llm_semantic",
                    "category": category,
                    "severity": _SEVERITY_LABEL[t.severity],
                    "title": t.explanation[:100] if t.explanation else f"LLM: {t.category.value}",
                    "description": t.explanation or "",
                    "title_en": t.explanation[:100] if t.explanation else f"LLM: {t.category.value}",
                    "description_en": t.explanation or "",
                    "location": {
                        "file_path": r.skill.file_path,
                        "line_number": 0,
                        "line_end": None,
                        "column_start": None,
                        "snippet": t.evidence[:500] if t.evidence else "",
                    },
                    "evidence": {
                        "matched_pattern": "llm_semantic_analysis",
                        "matched_content": t.evidence[:500] if t.evidence else "",
                        "context_before": "",
                        "context_after": "",
                    },
                    "threat_intel": None,
                    "remediation": None,
                    "metadata": {"llm_generated": True},
                    "references": [],
                })

        # Sort findings by severity (CRITICAL first)
        findings.sort(
            key=lambda f: -_SEVERITY_ORDER.get(
                Severity(f["severity"].lower()), 0
            )
        )

        # --- Verdict ---
        verdict_obj = self._compute_verdict(r, findings)

        # --- Stats ---
        severity_counter: dict[str, int] = {
            "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        category_counter: Counter[str] = Counter()
        for f in findings:
            severity_counter[f["severity"]] = severity_counter.get(
                f["severity"], 0) + 1
            category_counter[f["category"]] += 1

        analyzers_used = []
        if r.stage1:
            analyzers_used.append("static")
        if r.stage2:
            analyzers_used.append("llm_semantic")

        # Determine analyzer statuses
        analyzers_failed = []
        analyzers_skipped = []
        if r.stage2 and r.stage2.status == AnalyzerStatus.FAILED:
            analyzers_failed.append("llm_semantic")

        stats = {
            "total_findings": len(findings),
            "by_severity": severity_counter,
            "by_category": dict(category_counter),
            "analyzers_used": analyzers_used,
            "analyzers_failed": analyzers_failed,
            "analyzers_skipped": analyzers_skipped,
            "files_scanned": 1,
        }

        # --- Analyzer results ---
        analyzer_results: dict[str, Any] = {}
        if r.stage1:
            static_findings = [
                f for f in findings if f["analyzer_id"] == "static"]
            analyzer_results["static"] = {
                "analyzer_id": "static",
                "status": AnalyzerStatus.COMPLETED.value,
                "duration_ms": r.stage1.duration_ms,
                "findings": static_findings,
                "verdict": r.stage1.verdict.value.upper(),
                "verdict_confidence": 0.0,
                "extra": {},
                "error": None,
            }
        if r.stage2:
            llm_findings = [
                f for f in findings if f["analyzer_id"] == "llm_semantic"]
            analyzer_results["llm_semantic"] = {
                "analyzer_id": "llm_semantic",
                "status": r.stage2.status.value,
                "duration_ms": r.stage2.duration_ms,
                "findings": llm_findings,
                "verdict": r.stage2.verdict.value.upper(),
                "verdict_confidence": r.stage2.confidence,
                "extra": {
                    "llm_findings_count": len(llm_findings),
                },
                "error": r.stage2.summary if r.stage2.status == AnalyzerStatus.FAILED else None,
            }

        # --- Total scan duration ---
        total_ms = (r.stage1.duration_ms if r.stage1 else 0) + \
                   (r.stage2.duration_ms if r.stage2 else 0)

        return {
            "schema_version": "1.0",
            "scan_id": scan_id,
            "skill_name": r.skill.id,
            "skill_path": r.skill.file_path,
            "scan_timestamp": now.isoformat(),
            "scan_duration_ms": total_ms,
            "verdict": verdict_obj,
            "stats": stats,
            "findings": findings,
            "analyzer_results": analyzer_results,
            "skill_metadata": {
                "name": r.skill.id,
                "description": "",
                "allowed_tools": [],
                "file_count": 1,
                "binary_files": [],
                "has_pyc": False,
            },
            "scan_config": {
                "policy": "balanced",
                "analyzers_used": analyzers_used,
                "llm_enabled": r.stage2 is not None,
            },
        }

    def _compute_verdict(
        self, r: ScanResult, findings: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """Compute verdict combining Stage 1 findings and Stage 2 LLM assessment.

        When Stage 2 LLM has completed:
        - MALICIOUS → trust LLM, MALICIOUS/BLOCK
        - SUSPICIOUS → trust LLM, SUSPICIOUS/REVIEW
        - BENIGN/CLEAN → LLM overrides Stage 1 false positives, CLEAN/ALLOW
        - ERROR → fall back to Stage 1 findings-based logic

        When Stage 2 is absent (stage-1-only mode), use findings-based logic:
        - CRITICAL findings >= 1 → MALICIOUS, BLOCK
        - HIGH findings >= 1 or total >= 3 → SUSPICIOUS, REVIEW
        - Any finding → SUSPICIOUS, REVIEW
        - No findings → CLEAN, ALLOW
        """
        critical = sum(1 for f in findings if f["severity"] == "CRITICAL")
        high = sum(1 for f in findings if f["severity"] == "HIGH")
        total = len(findings)

        # Stage 2 LLM verdict takes priority when available and successful
        s2 = r.stage2
        has_llm_verdict = (
            s2 is not None and s2.status == AnalyzerStatus.COMPLETED
        )

        if has_llm_verdict:
            if s2.verdict == Verdict.MALICIOUS:
                result = Verdict.MALICIOUS
                action = RecommendedAction.BLOCK
                confidence = max(0.8, s2.confidence)
            elif s2.verdict == Verdict.SUSPICIOUS:
                result = Verdict.SUSPICIOUS
                action = RecommendedAction.REVIEW
                confidence = s2.confidence
            elif s2.verdict == Verdict.CLEAN:
                if critical >= 1:
                    # LLM says clean but Stage 1 has CRITICAL findings — downgrade
                    # to SUSPICIOUS for human review rather than silently allowing.
                    result = Verdict.SUSPICIOUS
                    action = RecommendedAction.REVIEW
                    confidence = min(s2.confidence, 0.5)
                else:
                    result = Verdict.CLEAN
                    action = RecommendedAction.ALLOW
                    confidence = s2.confidence
            else:
                has_llm_verdict = False

        if not has_llm_verdict:
            if critical >= 1:
                result = Verdict.MALICIOUS
                action = RecommendedAction.BLOCK
                confidence = max(0.8, r.stage2.confidence if r.stage2 else 0.8)
            elif high >= 1 or total >= 3:
                result = Verdict.SUSPICIOUS
                action = RecommendedAction.REVIEW
                confidence = r.stage2.confidence if r.stage2 else 0.6
            elif total > 0:
                result = Verdict.SUSPICIOUS
                action = RecommendedAction.REVIEW
                confidence = r.stage2.confidence if r.stage2 else 0.4
            else:
                result = Verdict.CLEAN
                action = RecommendedAction.ALLOW
                confidence = 1.0

        # Highest severity level (always based on findings, for informational purposes)
        if critical > 0:
            level = "CRITICAL"
        elif high > 0:
            level = "HIGH"
        elif any(f["severity"] == "MEDIUM" for f in findings):
            level = "MEDIUM"
        elif any(f["severity"] == "LOW" for f in findings):
            level = "LOW"
        elif any(f["severity"] == "INFO" for f in findings):
            level = "INFO"
        else:
            level = "SAFE"

        # Build severity breakdown string
        sev_parts = []
        for sev_name in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            cnt = sum(1 for f in findings if f["severity"] == sev_name)
            if cnt > 0:
                sev_parts.append(f"{sev_name} x {cnt}")
        sev_str = "，".join(sev_parts)

        # Category summary
        cat_counter: Counter[str] = Counter()
        for f in findings:
            cat_counter[f["category"]] += 1
        top_cats = "、".join(c for c, _ in cat_counter.most_common(3))

        # Key finding IDs (all findings, already sorted by severity)
        key_ids = [f["id"] for f in findings]

        if result == Verdict.MALICIOUS:
            summary = (
                f"检测到恶意威胁！共发现 {total} 个安全问题（{sev_str}），"
                f"主要威胁类型: {top_cats}。强烈建议拒绝安装该 Skill 包。"
            )
            summary_en = (
                f"Malicious threats detected! Found {total} security issues ({sev_str}), "
                f"primary threat types: {top_cats}. Strongly recommend rejecting installation."
            )
        elif result == Verdict.SUSPICIOUS:
            summary = (
                f"检测到可疑行为，共发现 {total} 个安全问题（{sev_str}），"
                f"主要威胁类型: {top_cats}。建议人工审查后决定。"
            )
            summary_en = (
                f"Suspicious behavior detected, found {total} security issues ({sev_str}), "
                f"primary threat types: {top_cats}. Recommend manual review."
            )
        elif result == Verdict.CLEAN and total > 0:
            summary = (
                f"规则扫描命中 {total} 个疑似问题（{sev_str}），"
                f"经 LLM 复验判定为安全，属于误报。"
            )
            summary_en = (
                f"Rule scan matched {total} potential issues ({sev_str}), "
                f"but LLM verification determined them as false positives."
            )
        else:
            summary = "未检测到安全威胁。"
            summary_en = "No security threats detected."

        return {
            "result": result.value.upper(),
            "confidence": round(confidence, 2),
            "level": level,
            "summary": summary,
            "summary_en": summary_en,
            "key_finding_ids": key_ids,
            "recommended_action": action.value.upper(),
        }

    # ------------------------------------------------------------------ #
    #  Summary report (batch-level)
    # ------------------------------------------------------------------ #

    def _build_summary(self, scan_id: str, results: list[ScanResult]) -> ScanSummary:
        threat_counter: Counter[str] = Counter()
        threat_skills: dict[str, list[str]] = {}
        source_stats: dict[str, dict] = {}
        clean = suspicious = malicious = 0
        suspicious_skills: list[str] = []
        malicious_skills: list[str] = []

        for r in results:
            v = r.final_verdict
            skill_path = r.skill.file_path
            if v == Verdict.CLEAN:
                clean += 1
            elif v == Verdict.SUSPICIOUS:
                suspicious += 1
                suspicious_skills.append(skill_path)
            elif v == Verdict.MALICIOUS:
                malicious += 1
                malicious_skills.append(skill_path)

            # Count threat types — only for non-clean results
            if v != Verdict.CLEAN:
                # Prefer Stage 2 (LLM) when available,
                # fall back to Stage 1 (rule matches) otherwise.
                if r.stage2 and r.stage2.threats:
                    for t in r.stage2.threats:
                        tcat = t.category.value
                        threat_counter[tcat] += 1
                        threat_skills.setdefault(tcat, []).append(
                            r.skill.file_path)
                elif r.stage1:
                    seen_rules = set()
                    for m in r.stage1.matched_rules:
                        cat = _RULE_CATEGORY_MAP.get(m.rule_name, m.rule_name)
                        if cat not in seen_rules:
                            threat_counter[cat] += 1
                            threat_skills.setdefault(cat, []).append(
                                r.skill.file_path)
                            seen_rules.add(cat)

            # Source breakdown
            src = r.skill.source
            if src not in source_stats:
                source_stats[src] = {"total": 0,
                                     "malicious": 0, "suspicious": 0}
            source_stats[src]["total"] += 1
            if v == Verdict.MALICIOUS:
                source_stats[src]["malicious"] += 1
            elif v == Verdict.SUSPICIOUS:
                source_stats[src]["suspicious"] += 1

        return ScanSummary(
            scan_id=scan_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            total_scanned=len(results),
            clean=clean,
            suspicious=suspicious,
            malicious=malicious,
            suspicious_skills=suspicious_skills,
            malicious_skills=malicious_skills,
            threat_type_counts=dict(threat_counter.most_common()),
            threat_type_skills=threat_skills,
            source_breakdown=source_stats,
        )

    def _write_summary_json(self, summary: ScanSummary) -> None:
        data = {
            "scan_id": summary.scan_id,
            "timestamp": summary.timestamp,
            "total_scanned": summary.total_scanned,
            "results": {
                "clean": summary.clean,
                "suspicious": summary.suspicious,
                "suspicious_skills": summary.suspicious_skills,
                "malicious": summary.malicious,
                "malicious_skills": summary.malicious_skills,
            },
            "top_threat_types": [
                {
                    "type": k,
                    "count": v,
                    "skills": summary.threat_type_skills.get(k, []),
                }
                for k, v in summary.threat_type_counts.items()
            ],
            "source_breakdown": summary.source_breakdown,
        }
        path = self._output_dir / "summary.json"
        path.write_text(json.dumps(data, ensure_ascii=False,
                        indent=2), encoding="utf-8")

    def _write_summary_md(self, summary: ScanSummary, results: list[ScanResult]) -> None:
        lines = [
            f"# Scan Report: {summary.scan_id}",
            "",
            f"**Timestamp**: {summary.timestamp}",
            f"**Total Scanned**: {summary.total_scanned}",
            "",
            "## Results Overview",
            "",
            "| Category | Count |",
            "|----------|-------|",
            f"| Clean | {summary.clean} |",
            f"| Suspicious | {summary.suspicious} |",
            f"| Malicious | {summary.malicious} |",
            "",
        ]

        if summary.malicious_skills:
            lines.append("### Malicious Skills")
            lines.append("")
            for fp in summary.malicious_skills:
                lines.append(f"- `{fp}`")
            lines.append("")

        if summary.suspicious_skills:
            lines.append("### Suspicious Skills")
            lines.append("")
            for fp in summary.suspicious_skills:
                lines.append(f"- `{fp}`")
            lines.append("")

        lines += [
            "## Top Threat Types",
            "",
        ]
        for t_type, count in summary.threat_type_counts.items():
            skill_files = summary.threat_type_skills.get(t_type, [])
            lines.append(f"### {t_type} ({count})")
            lines.append("")
            if skill_files:
                for fp in skill_files:
                    lines.append(f"- `{fp}`")
            else:
                lines.append("- (none)")
            lines.append("")

        lines += [
            "",
            "## Source Breakdown",
            "",
            "| Source | Total | Malicious | Suspicious |",
            "|--------|-------|-----------|------------|",
        ]
        for src, stats in summary.source_breakdown.items():
            lines.append(
                f"| {src} | {stats['total']} | {stats['malicious']} | {stats['suspicious']} |"
            )

        # Top 20 high-risk skills
        high_risk = sorted(
            [r for r in results if r.final_verdict in (
                Verdict.MALICIOUS, Verdict.SUSPICIOUS)],
            key=lambda r: (
                0 if r.final_verdict == Verdict.MALICIOUS else 1,
                -(r.stage2.confidence if r.stage2 else 0),
            ),
        )[:20]

        if high_risk:
            lines += [
                "",
                "## Top 20 High-Risk Skills",
                "",
                "| # | Skill ID | Source | Verdict | Confidence | Top Threat |",
                "|---|----------|--------|---------|------------|------------|",
            ]
            for i, r in enumerate(high_risk, 1):
                conf = f"{r.stage2.confidence:.2f}" if r.stage2 else "N/A"
                top_threat = r.stage2.threats[0].category.value if r.stage2 and r.stage2.threats else "-"
                lines.append(
                    f"| {i} | {r.skill.id} | {r.skill.source} | {r.final_verdict.value} | {conf} | {top_threat} |"
                )

        path = self._output_dir / "summary.md"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
