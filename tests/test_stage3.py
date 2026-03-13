"""Tests for Stage 3 reporter."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from scanner.models import (
    ScanResult,
    Severity,
    SkillFile,
    Stage1Result,
    Stage2Result,
    Threat,
    ThreatCategory,
    RuleMatch,
    Verdict,
)
from scanner.stage3.reporter import Reporter


def _make_skill(skill_id: str, source: str = "clawhub") -> SkillFile:
    return SkillFile(
        id=skill_id,
        source=source,
        file_path=f"skills/{source}/{skill_id}.md",
        content="test content",
        size_bytes=100,
    )


def _make_result(
    skill_id: str,
    source: str = "clawhub",
    verdict: Verdict = Verdict.CLEAN,
    stage2: Stage2Result | None = None,
    matched_rules: list[RuleMatch] | None = None,
) -> ScanResult:
    return ScanResult(
        skill=_make_skill(skill_id, source),
        stage1=Stage1Result(
            verdict=verdict if not stage2 else Verdict.SUSPICIOUS,
            matched_rules=matched_rules or [],
            duration_ms=1,
        ),
        stage2=stage2,
        final_verdict=stage2.verdict if stage2 else verdict,
    )


class TestReporter:
    def test_generate_summary(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            reporter = Reporter(tmpdir)
            results = [
                _make_result("s1", verdict=Verdict.CLEAN),
                _make_result("s2", verdict=Verdict.CLEAN),
                _make_result(
                    "s3",
                    verdict=Verdict.MALICIOUS,
                    stage2=Stage2Result(
                        verdict=Verdict.MALICIOUS,
                        confidence=0.95,
                        threats=[
                            Threat(
                                category=ThreatCategory.PROMPT_INJECTION,
                                severity=Severity.CRITICAL,
                                evidence="ignore instructions",
                                explanation="Override attempt",
                            )
                        ],
                        summary="Malicious",
                        duration_ms=100,
                    ),
                ),
            ]
            summary = reporter.generate("test-scan-001", results)
            assert summary.total_scanned == 3
            assert summary.clean == 2
            assert summary.malicious == 1

            # Check JSON report exists
            json_path = Path(tmpdir) / "summary.json"
            assert json_path.exists()
            data = json.loads(json_path.read_text())
            assert data["scan_id"] == "test-scan-001"
            assert data["results"]["malicious"] == 1

            # Check MD report exists
            md_path = Path(tmpdir) / "summary.md"
            assert md_path.exists()
            md_content = md_path.read_text()
            assert "test-scan-001" in md_content

            # Check threat detail report
            threat_path = Path(tmpdir) / "threats" / "s3.json"
            assert threat_path.exists()
            threat_data = json.loads(threat_path.read_text())
            assert threat_data["schema_version"] == "2.0"
            # v2.0 stats: by_analyzer present, old fields removed
            assert "by_analyzer" in threat_data["stats"]
            assert "analyzers_used" not in threat_data["stats"]
            assert "files_scanned" not in threat_data["stats"]
            # v2.0 key_finding_ids: at most 3
            assert len(threat_data["verdict"]["key_finding_ids"]) <= 3
            # v2.0 skill_metadata structure
            assert "trigger_description" in threat_data["skill_metadata"]
            assert "author" in threat_data["skill_metadata"]
            assert "version" in threat_data["skill_metadata"]
            assert "file_count" not in threat_data["skill_metadata"]
            # v2.0 scan_config structure
            assert "mode" in threat_data["scan_config"]
            assert "name" in threat_data["scan_config"]
            assert "disabled_rules" in threat_data["scan_config"]
            assert "policy" not in threat_data["scan_config"]

    def test_no_threat_reports_for_clean(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            reporter = Reporter(tmpdir)
            results = [
                _make_result("s1", verdict=Verdict.CLEAN),
            ]
            reporter.generate("test-scan-002", results)
            threats_dir = Path(tmpdir) / "threats"
            assert len(list(threats_dir.glob("*.json"))) == 0

    def test_source_breakdown(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            reporter = Reporter(tmpdir)
            results = [
                _make_result("s1", source="clawhub", verdict=Verdict.CLEAN),
                _make_result("s2", source="clawhub", verdict=Verdict.MALICIOUS),
                _make_result("s3", source="smithery", verdict=Verdict.CLEAN),
                _make_result("s4", source="skills_sh", verdict=Verdict.SUSPICIOUS),
            ]
            summary = reporter.generate("test-scan-003", results)
            assert "clawhub" in summary.source_breakdown
            assert summary.source_breakdown["clawhub"]["total"] == 2
            assert summary.source_breakdown["clawhub"]["malicious"] == 1
            assert summary.source_breakdown["skills_sh"]["suspicious"] == 1
