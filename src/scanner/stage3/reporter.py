"""Stage 3: Result aggregation and report generation."""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from scanner.models import ScanResult, ScanSummary, Severity, Verdict


class Reporter:
    def __init__(self, output_dir: str | Path):
        self._output_dir = Path(output_dir)
        self._threats_dir = self._output_dir / "threats"
        self._threats_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, scan_id: str, results: list[ScanResult]) -> ScanSummary:
        summary = self._build_summary(scan_id, results)
        self._write_threat_reports(results)
        self._write_summary_json(summary)
        self._write_summary_md(summary, results)
        return summary

    def _build_summary(self, scan_id: str, results: list[ScanResult]) -> ScanSummary:
        threat_counter: Counter[str] = Counter()
        threat_skills: dict[str, list[str]] = {}
        source_stats: dict[str, dict] = {}
        clean = suspicious = malicious = needs_review = errors = 0

        for r in results:
            v = r.final_verdict
            if v == Verdict.CLEAN or v == Verdict.BENIGN:
                clean += 1
            elif v == Verdict.SUSPICIOUS:
                suspicious += 1
            elif v == Verdict.MALICIOUS:
                malicious += 1
            elif v == Verdict.NEEDS_REVIEW:
                needs_review += 1
            elif v == Verdict.ERROR:
                errors += 1

            # Count threat types — prefer Stage 2 (LLM) when available,
            # fall back to Stage 1 (rule matches) otherwise.
            if r.stage2 and r.stage2.threats:
                for t in r.stage2.threats:
                    ttype = t.type.value
                    threat_counter[ttype] += 1
                    threat_skills.setdefault(ttype, []).append(r.skill.file_path)
            elif r.stage1:
                # Deduplicate by rule_name — count each rule type once per skill
                seen_rules = set()
                for m in r.stage1.matched_rules:
                    if m.rule_name not in seen_rules:
                        threat_counter[m.rule_name] += 1
                        threat_skills.setdefault(m.rule_name, []).append(
                            r.skill.file_path)
                        seen_rules.add(m.rule_name)

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
            needs_human_review=needs_review,
            scan_error=errors,
            threat_type_counts=dict(threat_counter.most_common()),
            threat_type_skills=threat_skills,
            source_breakdown=source_stats,
        )

    def _write_threat_reports(self, results: list[ScanResult]) -> None:
        for r in results:
            if r.final_verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS, Verdict.NEEDS_REVIEW):
                report = {
                    "skill_id": r.skill.id,
                    "source": r.skill.source,
                    "file_path": r.skill.file_path,
                    "verdict": r.final_verdict.value,
                    "scan_stages": {
                        "stage1": {
                            "result": r.stage1.verdict.value if r.stage1 else "not_run",
                            "matched_rules": [m.rule_id for m in r.stage1.matched_rules] if r.stage1 else [],
                            "duration_ms": r.stage1.duration_ms if r.stage1 else 0,
                        },
                    },
                }
                if r.stage2:
                    report["scan_stages"]["stage2"] = {
                        "result": r.stage2.verdict.value,
                        "confidence": r.stage2.confidence,
                        "threats": [
                            {
                                "type": t.type.value,
                                "severity": t.severity.value,
                                "evidence": t.evidence,
                                "explanation": t.explanation,
                            }
                            for t in r.stage2.threats
                        ],
                        "summary": r.stage2.summary,
                        "duration_ms": r.stage2.duration_ms,
                    }
                path = self._threats_dir / f"{r.skill.id}.json"
                path.write_text(json.dumps(
                    report, ensure_ascii=False, indent=2), encoding="utf-8")

    def _write_summary_json(self, summary: ScanSummary) -> None:
        data = {
            "scan_id": summary.scan_id,
            "timestamp": summary.timestamp,
            "total_scanned": summary.total_scanned,
            "results": {
                "clean": summary.clean,
                "suspicious": summary.suspicious,
                "malicious": summary.malicious,
                "needs_human_review": summary.needs_human_review,
                "scan_error": summary.scan_error,
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
            f"| Needs Human Review | {summary.needs_human_review} |",
            f"| Scan Error | {summary.scan_error} |",
            "",
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
                top_threat = r.stage2.threats[0].type.value if r.stage2 and r.stage2.threats else "-"
                lines.append(
                    f"| {i} | {r.skill.id} | {r.skill.source} | {r.final_verdict.value} | {conf} | {top_threat} |"
                )

        path = self._output_dir / "summary.md"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
