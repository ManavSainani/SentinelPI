"""The monitoring loop: collect on a schedule, poll auth logs, run detection, prune.

    python -m sentinelpi.monitor          # run until Ctrl+C / SIGTERM
    python -m sentinelpi.monitor --once   # run every task once, print results, exit

Each task runs in its own short database session and is isolated: a failure in one task is
recorded and logged by exception type only (messages can contain paths) and never stops the
others. Tasks are scheduled by a monotonic clock, so wall-clock changes cannot cause bursts.
"""

from __future__ import annotations

import argparse
import json
import logging
import signal
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

from pydantic import BaseModel

from sentinelpi.collectors import HostCollectors
from sentinelpi.collectors.auth_logs import AuthLogCollector, build_auth_collector
from sentinelpi.config import Settings, load_settings
from sentinelpi.detection.engine import DetectionEngine
from sentinelpi.storage import state_repo
from sentinelpi.storage.auth_ingest import poll_auth_logs
from sentinelpi.storage.db import Database
from sentinelpi.storage.ingest import store_metrics, store_snapshots
from sentinelpi.storage.retention import run_retention
from sentinelpi.timeutil import to_db, utc_now

log = logging.getLogger("sentinelpi.monitor")
HEARTBEAT_KEY = "monitor.heartbeat"


class TaskResult(BaseModel):
    task: str
    ok: bool
    detail: str | None = None


@dataclass
class _Task:
    name: str
    interval: float
    fn: Callable[[], str | None]
    next_due: float = 0.0


class Monitor:
    def __init__(
        self,
        settings: Settings,
        db: Database,
        *,
        collectors: HostCollectors | None = None,
        auth_collector: AuthLogCollector | None = None,
        engine: DetectionEngine | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.settings = settings
        self.db = db
        self._clock = clock
        self.collectors = collectors or HostCollectors(
            settings.collection, watchlist=settings.detection.watchlist.process_names
        )
        self.auth = auth_collector or build_auth_collector(settings.auth)
        self.engine = engine or DetectionEngine(settings.detection)
        m = settings.monitor
        self.tasks = [  # order matters on a combined cycle: collect, then judge
            _Task("metrics", m.metrics_interval_seconds, self._metrics),
            _Task("snapshots", m.snapshot_interval_seconds, self._snapshots),
            _Task("auth", m.auth_interval_seconds, self._auth),
            _Task("detection", m.detection_interval_seconds, self._detection),
            _Task("retention", m.retention_interval_seconds, self._retention),
        ]
        self.last_results: dict[str, TaskResult] = {}

    # ---- tasks (each returns an optional human-readable detail)
    def _metrics(self) -> str | None:
        result = self.collectors.metrics.collect()
        with self.db.session() as conn:
            stored = store_metrics(conn, result)
        return None if stored else f"metrics {result.status.state.value}"

    def _snapshots(self) -> str | None:
        procs, ports = self.collectors.processes.collect(), self.collectors.ports.collect()
        with self.db.session() as conn:
            report = store_snapshots(conn, procs, ports)
        return f"skipped: {', '.join(report.skipped)}" if report.skipped else None

    def _auth(self) -> str | None:
        with self.db.session() as conn:
            report = poll_auth_logs(conn, self.auth)
        if report.events_stored:
            log.info("stored %d new SSH auth event(s)", report.events_stored)
        return None if report.state.value == "ok" else f"{report.state.value}: {report.detail}"

    def _detection(self) -> str | None:
        with self.db.session() as conn:
            report = self.engine.run(conn)
            state_repo.set_state(conn, HEARTBEAT_KEY, to_db(utc_now()))
        for r in report.rules:
            if r.fired:
                log.warning("%s fired %d detection(s)", r.rule_id, r.fired)
        errors = [f"{r.rule_id}:{r.detail}" for r in report.rules if r.state == "error"]
        return f"rule errors: {', '.join(errors)}" if errors else None

    def _retention(self) -> str | None:
        with self.db.session() as conn:
            report = run_retention(conn, self.settings.retention)
        return None if report.size_target_met else "database exceeds its size target"

    # ---- scheduling
    def _run_task(self, task: _Task) -> TaskResult:
        try:
            detail = task.fn()
            result = TaskResult(task=task.name, ok=True, detail=detail)
        except Exception as exc:  # noqa: BLE001 - isolate failures
            log.warning("task %s failed: %s", task.name, type(exc).__name__)
            result = TaskResult(task=task.name, ok=False, detail=type(exc).__name__)
        self.last_results[task.name] = result
        return result

    def run_due(self) -> list[TaskResult]:
        now = self._clock()
        results: list[TaskResult] = []
        for task in self.tasks:
            if task.next_due <= now:
                results.append(self._run_task(task))
                task.next_due = self._clock() + task.interval  # no catch-up bursts
        return results

    def run_all_once(self) -> list[TaskResult]:
        return [self._run_task(t) for t in self.tasks]

    def seconds_until_next(self) -> float:
        return max(0.0, min(t.next_due for t in self.tasks) - self._clock())

    def run_forever(self, stop: threading.Event, warmup_seconds: float = 1.0) -> None:
        # CPU counters need a baseline interval before the first reading is meaningful.
        if stop.wait(warmup_seconds):
            return
        while not stop.is_set():
            self.run_due()
            stop.wait(min(1.0, max(0.05, self.seconds_until_next())))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m sentinelpi.monitor")
    parser.add_argument("--once", action="store_true", help="run each task once and exit")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    settings = load_settings()
    db = Database(settings.storage.db_path)
    db.migrate()
    monitor = Monitor(settings, db)

    if args.once:
        time.sleep(1.0)
        print(json.dumps([r.model_dump() for r in monitor.run_all_once()], indent=2))
        return 0

    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    log.info("monitoring started; database %s (Ctrl+C to stop)", db.path)
    monitor.run_forever(stop)
    log.info("monitoring stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
