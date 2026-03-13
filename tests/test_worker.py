"""Tests for the worker module (config, downloader, mongo_store, task_runner, consumer)."""

from __future__ import annotations

import json
import tempfile
import textwrap
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from scanner.models import (
    AnalyzerStatus,
    ScanResult,
    Severity,
    SkillFile,
    Stage1Result,
    Stage2Result,
    RuleMatch,
    Verdict,
)
from scanner.worker.config import (
    MongoConfig,
    RabbitMQConfig,
    ScanConfig,
    WorkerConfig,
    load_config,
)


# ------------------------------------------------------------------ #
#  config.py
# ------------------------------------------------------------------ #


class TestLoadConfig:
    def test_load_full_config(self, tmp_path: Path):
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text(textwrap.dedent("""\
            rabbitmq:
              host: mq.example.com
              port: 5673
              username: admin
              password: secret
              vhost: /prod
              queue_name: scan.queue
              prefetch_count: 2
              heartbeat: 300
              max_retries: 5
            mongodb:
              uri: mongodb://localhost:27017
              database: mydb
              tasks_collection: my_tasks
              reports_collection: my_reports
            scan:
              stage: "1"
              model: gpt-4
              api_key_env: MY_KEY
        """))

        config = load_config(cfg_file)
        assert config.rabbitmq.host == "mq.example.com"
        assert config.rabbitmq.port == 5673
        assert config.rabbitmq.vhost == "/prod"
        assert config.rabbitmq.max_retries == 5
        assert config.mongodb.database == "mydb"
        assert config.scan.stage == "1"
        assert config.scan.model == "gpt-4"

    def test_load_defaults_on_missing_file(self, tmp_path: Path):
        config = load_config(tmp_path / "nonexistent.yaml")
        assert config.rabbitmq.host == "localhost"
        assert config.mongodb.uri == "mongodb://localhost:27017"
        assert config.scan.stage == "full"

    def test_partial_config(self, tmp_path: Path):
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text("rabbitmq:\n  host: myhost\n")
        config = load_config(cfg_file)
        assert config.rabbitmq.host == "myhost"
        assert config.rabbitmq.port == 5672  # default
        assert config.mongodb.database == "skillscan"  # default

    def test_ignores_unknown_keys(self, tmp_path: Path):
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text("rabbitmq:\n  host: h\n  unknown_key: 123\n")
        config = load_config(cfg_file)
        assert config.rabbitmq.host == "h"


# ------------------------------------------------------------------ #
#  downloader.py
# ------------------------------------------------------------------ #


class TestDownloader:
    def _make_skill_zip(self, tmp_path: Path) -> Path:
        """Create a zip containing a SKILL.md file."""
        skill_dir = tmp_path / "skill_src"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text("# Test Skill\nDo something safe.")

        zip_path = tmp_path / "skill.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.write(skill_dir / "SKILL.md", "SKILL.md")
        return zip_path

    @patch("scanner.worker.downloader.requests.get")
    def test_download_and_load_zip(self, mock_get, tmp_path: Path):
        from scanner.worker.downloader import download_and_load

        zip_path = self._make_skill_zip(tmp_path)
        zip_bytes = zip_path.read_bytes()

        mock_resp = MagicMock()
        mock_resp.iter_content.return_value = [zip_bytes]
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        skill = download_and_load("https://example.com/skills/test.zip")
        assert isinstance(skill, SkillFile)
        assert "Test Skill" in skill.content
        assert skill.size_bytes > 0

    @patch("scanner.worker.downloader.requests.get")
    def test_download_single_file(self, mock_get):
        from scanner.worker.downloader import download_and_load

        content = "# Simple Skill\nJust a markdown file."
        mock_resp = MagicMock()
        mock_resp.iter_content.return_value = [content.encode()]
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        skill = download_and_load("https://example.com/skill.md")
        assert "Simple Skill" in skill.content

    @patch("scanner.worker.downloader.requests.get")
    def test_download_presigned_url(self, mock_get, tmp_path: Path):
        """URLs with long query params (S3 presigned) must not cause OSError."""
        from scanner.worker.downloader import download_and_load

        zip_path = self._make_skill_zip(tmp_path)
        zip_bytes = zip_path.read_bytes()

        mock_resp = MagicMock()
        mock_resp.iter_content.return_value = [zip_bytes]
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        long_url = (
            "https://oss.example.com/bucket/malicious-exfiltrator.zip"
            "?X-Amz-Algorithm=AWS4-HMAC-SHA256"
            "&X-Amz-Credential=AKID%2F20260312%2Fdefault%2Fs3%2Faws4_request"
            "&X-Amz-Date=20260312T131106Z"
            "&X-Amz-Expires=7200"
            "&X-Amz-Signature=" + "a" * 200
        )
        skill = download_and_load(long_url)
        assert isinstance(skill, SkillFile)
        assert "malicious-exfiltrator" in skill.id
        assert "Test Skill" in skill.content

    def test_filename_from_url(self):
        from scanner.worker.downloader import _filename_from_url

        assert _filename_from_url("https://a.com/bucket/test.zip?X-Amz=foo") == "test.zip"
        assert _filename_from_url("https://a.com/path/to/skill.md") == "skill.md"
        assert _filename_from_url("https://a.com/") == "unnamed"
        assert _filename_from_url("https://a.com/file.zip?a=1&b=2") == "file.zip"


# ------------------------------------------------------------------ #
#  mongo_store.py
# ------------------------------------------------------------------ #


class TestMongoStore:
    def _make_store(self):
        from scanner.worker.mongo_store import MongoStore

        config = MongoConfig(uri="mongodb://localhost:27017", database="test_db")
        with patch("scanner.worker.mongo_store.MongoClient") as MockClient:
            mock_db = MagicMock()
            MockClient.return_value.__getitem__ = MagicMock(return_value=mock_db)
            mock_tasks = MagicMock()
            mock_reports = MagicMock()
            mock_db.__getitem__ = MagicMock(side_effect=lambda k: {
                "tasks": mock_tasks,
                "reports": mock_reports,
            }[k])

            store = MongoStore(config)
            store._tasks = mock_tasks
            store._reports = mock_reports
            return store, mock_tasks, mock_reports

    def test_update_task_status_found(self):
        store, mock_tasks, _ = self._make_store()
        mock_tasks.update_one.return_value = MagicMock(matched_count=1)
        store.update_task_status("task123", "processing")
        mock_tasks.update_one.assert_called_once()
        call_args = mock_tasks.update_one.call_args
        assert call_args[0][0] == {"task_id": "task123"}
        assert call_args[0][1]["$set"]["status"] == "processing"

    def test_update_task_status_not_found_no_error(self):
        store, mock_tasks, _ = self._make_store()
        mock_tasks.update_one.return_value = MagicMock(matched_count=0)
        store.update_task_status("missing_task", "processing")

    def test_update_task_status_with_error(self):
        store, mock_tasks, _ = self._make_store()
        mock_tasks.update_one.return_value = MagicMock(matched_count=1)
        store.update_task_status("task123", "failed", error="download failed")
        call_args = mock_tasks.update_one.call_args
        assert call_args[0][1]["$set"]["error"] == "download failed"

    def test_save_report_upsert(self):
        store, _, mock_reports = self._make_store()
        store.save_report("task123", "scan-001", {"verdict": "CLEAN"})
        mock_reports.replace_one.assert_called_once()
        call_args = mock_reports.replace_one.call_args
        assert call_args[0][0] == {"task_id": "task123"}
        assert call_args[1]["upsert"] is True


# ------------------------------------------------------------------ #
#  task_runner.py
# ------------------------------------------------------------------ #


class TestTaskRunner:
    def _make_runner(self):
        from scanner.worker.task_runner import TaskRunner

        config = ScanConfig(stage="full", api_key_env="ARK_API_KEY")
        mongo = MagicMock()
        runner = TaskRunner(config, mongo)
        return runner, mongo

    @patch("scanner.worker.task_runner.download_and_load")
    def test_execute_stage1_only_clean(self, mock_download):
        runner, mongo = self._make_runner()
        runner._config = ScanConfig(stage="1")

        mock_download.return_value = SkillFile(
            id="test-skill",
            source="unknown",
            file_path="test.md",
            content="This is a perfectly clean skill.",
            size_bytes=30,
        )

        task_msg = {
            "task_id": "abc123",
            "skill_download_url": "https://example.com/skill.zip",
            "scan_options": {"enable_llm": False},
        }

        runner.execute(task_msg)

        mongo.update_task_status.assert_any_call("abc123", "processing")
        mongo.save_report.assert_called_once()
        final_call = [c for c in mongo.update_task_status.call_args_list
                      if c[0][1] == "completed"]
        assert len(final_call) == 1

    @patch("scanner.worker.task_runner.download_and_load")
    def test_execute_download_failure_raises(self, mock_download):
        runner, mongo = self._make_runner()
        mock_download.side_effect = ConnectionError("timeout")

        task_msg = {
            "task_id": "fail_task",
            "skill_download_url": "https://bad-url.com/x.zip",
            "scan_options": {},
        }

        with pytest.raises(ConnectionError):
            runner.execute(task_msg)


# ------------------------------------------------------------------ #
#  consumer.py
# ------------------------------------------------------------------ #


class TestConsumer:
    def test_get_retry_count_no_headers(self):
        from scanner.worker.consumer import Consumer

        props = MagicMock()
        props.headers = None
        assert Consumer._get_retry_count(props) == 0

    def test_get_retry_count_with_header(self):
        from scanner.worker.consumer import Consumer

        props = MagicMock()
        props.headers = {"x-retry-count": 2}
        assert Consumer._get_retry_count(props) == 2

    def test_get_retry_count_first_attempt(self):
        from scanner.worker.consumer import Consumer

        props = MagicMock()
        props.headers = {"other-header": "val"}
        assert Consumer._get_retry_count(props) == 0


# ------------------------------------------------------------------ #
#  reporter.build_skill_report (public API)
# ------------------------------------------------------------------ #


class TestReporterPublicAPI:
    def test_build_skill_report_returns_dict(self):
        from scanner.stage3.reporter import Reporter

        with tempfile.TemporaryDirectory() as tmp:
            reporter = Reporter(tmp)

            skill = SkillFile(
                id="test-skill",
                source="clawhub",
                file_path="skills/test/SKILL.md",
                content="Some skill content here.",
                size_bytes=24,
            )
            stage1 = Stage1Result(
                verdict=Verdict.SUSPICIOUS,
                matched_rules=[
                    RuleMatch(
                        rule_id="PI-001",
                        rule_name="instruction_override",
                        severity=Severity.CRITICAL,
                        matched_text="ignore all previous",
                        position=(0, 19),
                        pattern="ignore.*previous",
                    )
                ],
                duration_ms=5,
            )
            result = ScanResult(
                skill=skill,
                stage1=stage1,
                final_verdict=Verdict.SUSPICIOUS,
            )

            report = reporter.build_skill_report(result, "scan-test-001")
            assert isinstance(report, dict)
            assert report["schema_version"] == "1.0"
            assert report["scan_id"] == "scan-test-001"
            assert report["verdict"]["result"] in ("MALICIOUS", "SUSPICIOUS", "CLEAN")
            assert len(report["findings"]) > 0
