"""MongoDB storage layer for task status and scan reports."""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from pymongo import MongoClient
from pymongo.collection import Collection

from scanner.worker.config import MongoConfig

logger = logging.getLogger(__name__)

_MAX_REPORT_BYTES = 12 * 1024 * 1024  # 12 MB
_MAX_INLINE_FINDINGS = 500


class MongoStore:
    """Thread-safe MongoDB client for task management and report persistence."""

    def __init__(self, config: MongoConfig):
        self._client = MongoClient(config.uri)
        db = self._client[config.database]
        self._tasks: Collection = db[config.tasks_collection]
        self._reports: Collection = db[config.reports_collection]
        self._findings: Collection = db["findings"]
        self._ensure_indexes()

    def _ensure_indexes(self) -> None:
        self._tasks.create_index("task_id", unique=True, background=True)
        self._reports.create_index("task_id", unique=True, background=True)
        self._findings.create_index("ref_id", unique=True, background=True)

    def close(self) -> None:
        self._client.close()

    # ------------------------------------------------------------------ #
    #  Task status
    # ------------------------------------------------------------------ #

    def update_task_status(
        self,
        task_id: str,
        status: str,
        *,
        error: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        """Update task status.  If the task_id is not found, log a warning
        and continue — the scan should still proceed."""
        update: dict[str, Any] = {
            "$set": {
                "status": status,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
        }
        if error is not None:
            update["$set"]["error"] = error
        if extra:
            update["$set"].update(extra)

        result = self._tasks.update_one({"task_id": task_id}, update)
        if result.matched_count == 0:
            logger.warning("Task %s not found in DB, continuing anyway", task_id)

    # ------------------------------------------------------------------ #
    #  Report persistence
    # ------------------------------------------------------------------ #

    def save_report(
        self,
        task_id: str,
        scan_id: str,
        report: dict[str, Any],
    ) -> None:
        """Upsert the scan report keyed by task_id (idempotent).

        When the report exceeds size limits (>12 MB or >500 inline findings),
        findings are stored in a separate collection and the report carries
        a ``findings_ref`` pointer instead.
        """
        report = dict(report)
        findings = report.get("findings", [])
        needs_split = len(findings) > _MAX_INLINE_FINDINGS

        if not needs_split:
            raw_size = len(json.dumps(report, ensure_ascii=False).encode("utf-8"))
            needs_split = raw_size > _MAX_REPORT_BYTES

        if needs_split:
            ref_id = f"findings_{scan_id}_{uuid.uuid4().hex[:8]}"
            self._findings.replace_one(
                {"ref_id": ref_id},
                {"ref_id": ref_id, "scan_id": scan_id, "findings": findings},
                upsert=True,
            )
            report["findings"] = []
            report["findings_ref"] = ref_id
            report["findings_stored_separately"] = True
            logger.info(
                "Task %s: %d findings stored separately (ref=%s)",
                task_id, len(findings), ref_id,
            )

        doc = {
            "task_id": task_id,
            "scan_id": scan_id,
            **report,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        self._reports.replace_one({"task_id": task_id}, doc, upsert=True)
        logger.info("Report saved for task %s (scan %s)", task_id, scan_id)
