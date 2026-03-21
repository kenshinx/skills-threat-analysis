"""Local CLI to run a worker-style scan on a single ZIP and print the report."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import shutil
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

from scanner.models import AnalyzerStatus, ScanResult, Verdict
from scanner.stage1.engine import RuleEngine
from scanner.stage2.analyzer import SemanticAnalyzer
from scanner.stage3.reporter import Reporter
from scanner.worker.config import ScanConfig, load_config
from scanner.worker.downloader import _load_from_zip

logger = logging.getLogger(__name__)


def _merge_verdict(result: ScanResult, s2) -> Verdict:
    """Merge Stage 1 and Stage 2 verdicts (mirrors TaskRunner logic)."""
    if s2.status == AnalyzerStatus.FAILED:
        return result.stage1.verdict if result.stage1 else Verdict.SUSPICIOUS
    if s2.verdict == Verdict.MALICIOUS:
        return Verdict.MALICIOUS
    if s2.verdict == Verdict.SUSPICIOUS:
        return Verdict.SUSPICIOUS
    if s2.verdict == Verdict.CLEAN and s2.confidence >= 0.7:
        return Verdict.CLEAN
    return Verdict.SUSPICIOUS


def _scan_single_skill(skill_zip: Path, scan_cfg: ScanConfig, enable_llm: bool) -> ScanResult:
    """Run Stage 1 (+ optional Stage 2) on a single skill loaded from a local ZIP."""
    # Reuse worker downloader's ZIP loading logic in an isolated temp dir,
    # mirroring download_and_load() to avoid reusing a persistent 'extracted' dir.
    with tempfile.TemporaryDirectory() as tmp_root:
        tmp = Path(tmp_root)
        archive_path = tmp / "skill_archive"
        shutil.copy2(skill_zip, archive_path)
        # The 'url' parameter is only used for ID/path derivation, so passing
        # the original local path is sufficient and keeps IDs stable.
        skill = _load_from_zip(archive_path, skill_zip.as_posix())

    rule_engine = RuleEngine()
    stage1 = rule_engine.scan(skill.content)

    result = ScanResult(
        skill=skill,
        stage1=stage1,
        final_verdict=stage1.verdict,
    )
    st = scan_cfg.stage
    if st == "1":
        want_stage2 = False
    elif st in ("full-llm", "2"):
        want_stage2 = True
    elif st == "full":
        want_stage2 = stage1.verdict != Verdict.CLEAN
    else:
        want_stage2 = False

    need_stage2 = enable_llm and want_stage2

    if not need_stage2:
        return result

    api_key = scan_cfg.api_key or os.environ.get(scan_cfg.api_key_env)
    if not api_key:
        logger.warning(
            "Stage 2 skipped: set scan.api_key in config or export %s",
            scan_cfg.api_key_env,
        )
        return result

    analyzer = SemanticAnalyzer(
        model=scan_cfg.model,
        api_key=api_key,
        api_base=scan_cfg.api_base,
        concurrency=scan_cfg.concurrency,
        batch_size=scan_cfg.batch_size,
    )
    items = [(skill.id, skill.content, stage1.matched_rules)]
    # Reuse the same async entrypoint as the real worker (TaskRunner).
    s2 = asyncio.run(analyzer.analyze_batch(items))[0]
    result.stage2 = s2
    result.final_verdict = _merge_verdict(result, s2)
    return result


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="scan-worker-zip",
        description="Run a worker-style scan on a single ZIP and print the JSON report.",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("config.yaml"),
        help="Path to the worker config YAML file (default: config.yaml)",
    )
    parser.add_argument(
        "--zip",
        required=True,
        type=Path,
        help="Path to the local ZIP file to scan.",
    )
    parser.add_argument(
        "--enable-llm",
        action="store_true",
        help="Enable Stage 2 LLM semantic analysis (uses scan.* config).",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Logging level (default: INFO)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    if not args.zip.exists():
        logger.error("ZIP file not found: %s", args.zip)
        raise SystemExit(1)

    cfg = load_config(args.config)

    # Run scan
    scan_result = _scan_single_skill(args.zip, cfg.scan, enable_llm=args.enable_llm)

    # Build report using the same reporter as the worker.
    scan_id = (
        f"scan-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
        f"-{uuid.uuid4().hex[:6]}"
    )
    reporter = Reporter(tempfile.mkdtemp(prefix="worker_local_report_"))
    report = reporter.build_skill_report(scan_result, scan_id)

    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

