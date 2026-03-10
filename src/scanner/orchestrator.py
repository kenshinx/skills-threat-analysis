"""Orchestrator: coordinate the three-stage scanning pipeline."""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator

from scanner.loader import load_skills
from scanner.models import ScanResult, SkillFile, Verdict
from scanner.stage1.engine import RuleEngine
from scanner.stage2.analyzer import SemanticAnalyzer
from scanner.stage3.reporter import Reporter

logger = logging.getLogger(__name__)


class Orchestrator:
    def __init__(
        self,
        skills_dir: str | Path,
        output_dir: str | Path = "./report",
        stage: str = "full",
        severity_filter: str = "all",
        batch_size: int = 5,
        concurrency: int = 3,
        resume_scan_id: str | None = None,
    ):
        self._skills_dir = Path(skills_dir)
        self._output_dir = Path(output_dir)
        self._output_dir.mkdir(parents=True, exist_ok=True)
        self._stage = stage
        self._severity_filter = severity_filter
        self._batch_size = batch_size
        self._concurrency = concurrency
        self._rule_engine = RuleEngine()
        self._reporter = Reporter(self._output_dir)

        if resume_scan_id:
            self._scan_id = resume_scan_id
            self._checkpoint = self._load_checkpoint()
        else:
            self._scan_id = f"scan-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
            self._checkpoint: dict | None = None

    def run(self) -> None:
        """Main entry point — runs the full scan pipeline."""
        logger.info("Starting scan %s on %s", self._scan_id, self._skills_dir)

        # Stage 1
        stage1_results = self._run_stage1()
        logger.info(
            "Stage 1 complete: %d total, %d clean, %d suspicious, %d needs_review",
            len(stage1_results),
            sum(1 for r in stage1_results if r.stage1.verdict == Verdict.CLEAN),
            sum(1 for r in stage1_results if r.stage1.verdict == Verdict.SUSPICIOUS),
            sum(1 for r in stage1_results if r.stage1.verdict == Verdict.NEEDS_REVIEW),
        )

        if self._stage == "1":
            # Finalize with stage 1 only
            for r in stage1_results:
                r.final_verdict = r.stage1.verdict
            self._reporter.generate(self._scan_id, stage1_results)
            logger.info("Stage-1-only scan complete. Report at %s", self._output_dir)
            return

        # Stage 2 — only for NEEDS_REVIEW items
        results = asyncio.run(self._run_stage2(stage1_results))

        # Stage 3 — report
        summary = self._reporter.generate(self._scan_id, results)
        logger.info(
            "Scan complete. Malicious: %d, Suspicious: %d, Clean: %d. Report at %s",
            summary.malicious, summary.suspicious, summary.clean, self._output_dir,
        )

    def _run_stage1(self) -> list[ScanResult]:
        results: list[ScanResult] = []
        processed = 0

        for skill in load_skills(self._skills_dir):
            # Skip if resuming past checkpoint
            if self._checkpoint and processed < self._checkpoint.get("stage1_completed", 0):
                processed += 1
                continue

            stage1 = self._rule_engine.scan(skill.content)
            results.append(ScanResult(
                skill=skill,
                stage1=stage1,
                final_verdict=stage1.verdict,
            ))
            processed += 1

            if processed % 10000 == 0:
                logger.info("Stage 1 progress: %d files processed", processed)

        return results

    async def _run_stage2(self, stage1_results: list[ScanResult]) -> list[ScanResult]:
        analyzer = SemanticAnalyzer(
            concurrency=self._concurrency,
            batch_size=self._batch_size,
        )

        needs_review = [r for r in stage1_results if r.stage1.verdict == Verdict.NEEDS_REVIEW]
        # SUSPICIOUS from Stage 1 also gets LLM analysis for confidence scoring
        suspicious = [r for r in stage1_results if r.stage1.verdict == Verdict.SUSPICIOUS]
        to_analyze = needs_review + suspicious

        logger.info("Stage 2: analyzing %d skills with LLM", len(to_analyze))

        # Process in batches
        checkpoint_index = 0
        if self._checkpoint:
            checkpoint_index = self._checkpoint.get("stage2_completed", 0)

        for batch_start in range(checkpoint_index, len(to_analyze), self._batch_size):
            batch = to_analyze[batch_start:batch_start + self._batch_size]
            items = [
                (r.skill.id, r.skill.content, r.stage1.matched_rules)
                for r in batch
            ]
            stage2_results = await analyzer.analyze_batch(items)

            for r, s2 in zip(batch, stage2_results):
                r.stage2 = s2
                # Determine final verdict
                if s2.verdict == Verdict.MALICIOUS:
                    r.final_verdict = Verdict.MALICIOUS
                elif s2.verdict == Verdict.SUSPICIOUS:
                    r.final_verdict = Verdict.SUSPICIOUS
                elif s2.verdict == Verdict.BENIGN:
                    # Stage 1 was SUSPICIOUS but LLM says BENIGN → downgrade
                    r.final_verdict = Verdict.CLEAN
                elif s2.confidence < 0.7:
                    r.final_verdict = Verdict.NEEDS_REVIEW
                else:
                    r.final_verdict = s2.verdict

            # Save checkpoint
            self._save_checkpoint(
                stage1_completed=len(stage1_results),
                stage2_completed=batch_start + len(batch),
                stage2_total=len(to_analyze),
            )

            completed = batch_start + len(batch)
            logger.info("Stage 2 progress: %d/%d", completed, len(to_analyze))

        # Skills that were CLEAN in Stage 1 keep their verdict
        return stage1_results

    def _save_checkpoint(self, stage1_completed: int, stage2_completed: int, stage2_total: int) -> None:
        cp = {
            "scan_id": self._scan_id,
            "stage1_completed": stage1_completed,
            "stage2_completed": stage2_completed,
            "stage2_remaining": stage2_total - stage2_completed,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        path = self._output_dir / "checkpoint.json"
        path.write_text(json.dumps(cp, indent=2), encoding="utf-8")

    def _load_checkpoint(self) -> dict | None:
        path = self._output_dir / "checkpoint.json"
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8"))
            if data.get("scan_id") == self._scan_id:
                logger.info("Resuming scan %s from checkpoint", self._scan_id)
                return data
        return None
