"""CLI entry point for the RabbitMQ worker mode.

Supports running a single worker or spawning multiple worker processes
with a built-in supervisor that auto-restarts crashed children.
"""

from __future__ import annotations

import argparse
import logging
import multiprocessing
import os
import signal
import sys
import time
from pathlib import Path

from scanner.worker.config import load_config

logger = logging.getLogger(__name__)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="scan-worker",
        description="Start a RabbitMQ worker that consumes scan tasks and writes reports to MongoDB.",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("config.yaml"),
        help="Path to the worker config YAML file (default: config.yaml)",
    )
    parser.add_argument(
        "--workers", "-w",
        type=int,
        default=1,
        help="Number of parallel worker processes (default: 1)",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Logging level (default: INFO)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Shorthand for --log-level DEBUG",
    )
    return parser.parse_args(argv)


def _setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level),
        format="%(asctime)s [%(levelname)s] %(name)s [%(process)d]: %(message)s",
    )
    for noisy in ("httpcore", "httpx", "openai", "pika"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def _run_single_worker(config_path: Path) -> None:
    """Run a single worker in the current process (used as the child target)."""
    from scanner.worker.consumer import Consumer
    from scanner.worker.mongo_store import MongoStore
    from scanner.worker.task_runner import TaskRunner

    config = load_config(config_path)
    mongo = MongoStore(config.mongodb)
    runner = TaskRunner(config.scan, mongo)
    consumer = Consumer(config.rabbitmq, runner, mongo)
    try:
        consumer.start()
    finally:
        mongo.close()


# ------------------------------------------------------------------ #
#  Multi-process supervisor
# ------------------------------------------------------------------ #

_RESTART_DELAY = 2  # seconds before restarting a crashed worker


class _Supervisor:
    """Manage N worker child processes with auto-restart on crash."""

    def __init__(self, num_workers: int, config_path: Path):
        self._num_workers = num_workers
        self._config_path = config_path
        self._children: dict[int, multiprocessing.Process] = {}
        self._shutdown = False

    def start(self) -> None:
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)

        logger.info("Supervisor starting %d worker(s)", self._num_workers)
        for i in range(self._num_workers):
            self._spawn(i)

        while not self._shutdown:
            for idx, proc in list(self._children.items()):
                if not proc.is_alive():
                    exit_code = proc.exitcode
                    if self._shutdown:
                        break
                    logger.warning(
                        "Worker #%d (pid %s) exited with code %s — restarting in %ds",
                        idx, proc.pid, exit_code, _RESTART_DELAY,
                    )
                    time.sleep(_RESTART_DELAY)
                    self._spawn(idx)
            time.sleep(0.5)

        self._wait_for_children()

    def _spawn(self, index: int) -> None:
        proc = multiprocessing.Process(
            target=_run_single_worker,
            args=(self._config_path,),
            name=f"scan-worker-{index}",
            daemon=False,
        )
        proc.start()
        self._children[index] = proc
        logger.info("Worker #%d started (pid %d)", index, proc.pid)

    def _handle_signal(self, signum: int, _frame) -> None:
        sig_name = signal.Signals(signum).name
        logger.info("Supervisor received %s — stopping all workers …", sig_name)
        self._shutdown = True
        for proc in self._children.values():
            if proc.is_alive():
                os.kill(proc.pid, signal.SIGTERM)

    def _wait_for_children(self) -> None:
        for idx, proc in self._children.items():
            proc.join(timeout=30)
            if proc.is_alive():
                logger.warning("Worker #%d did not exit in time, killing", idx)
                proc.kill()
                proc.join(timeout=5)
        logger.info("All workers stopped")


# ------------------------------------------------------------------ #


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    _setup_logging("DEBUG" if args.verbose else args.log_level)

    if not args.config.exists():
        logger.error("Config file not found: %s", args.config)
        sys.exit(1)

    if args.workers < 1:
        logger.error("--workers must be >= 1")
        sys.exit(1)

    if args.workers == 1:
        _run_single_worker(args.config)
    else:
        _Supervisor(args.workers, args.config).start()


if __name__ == "__main__":
    main()
