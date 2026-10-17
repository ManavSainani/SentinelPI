"""Run the rules, apply cooldowns, and store detection events.

Anti-noise: every detection carries a dedupe key. If the same key fired within its rule's
cooldown, the new detection is suppressed (and counted), so one persistent condition yields
one event per cooldown instead of one per evaluation. A failing rule is isolated: it is
reported as an error and the other rules still run.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta
from typing import Literal

from pydantic import BaseModel

from sentinelpi.config import DetectionSettings
from sentinelpi.detection.base import Rule
from sentinelpi.detection.rules.cpu import CpuRule
from sentinelpi.detection.rules.new_port import NewPortRule
from sentinelpi.detection.rules.ssh_failures import SshFailuresRule
from sentinelpi.detection.rules.watchlist import WatchlistRule
from sentinelpi.storage import detection_repo, events_repo
from sentinelpi.timeutil import utc_now


class RuleStatus(BaseModel):
    rule_id: str
    name: str
    state: Literal["ok", "skipped", "disabled", "error"]
    detail: str | None = None
    fired: int = 0
    suppressed: int = 0


class DetectionReport(BaseModel):
    ran_at: datetime
    rules: list[RuleStatus]

    @property
    def events_created(self) -> int:
        return sum(r.fired for r in self.rules)


def build_rules(settings: DetectionSettings) -> list[Rule]:
    max_age = timedelta(minutes=settings.max_snapshot_age_minutes)
    scoring = settings.scoring
    return [
        SshFailuresRule(settings.ssh_failures, scoring),
        NewPortRule(settings.new_port, scoring, max_age),
        CpuRule(settings.cpu, scoring),
        WatchlistRule(settings.watchlist, scoring, max_age),
    ]


class DetectionEngine:
    def __init__(self, settings: DetectionSettings, rules: list[Rule] | None = None) -> None:
        self.settings = settings
        self.rules = rules if rules is not None else build_rules(settings)

    def run(self, conn: sqlite3.Connection, now: datetime | None = None) -> DetectionReport:
        now = now or utc_now()
        detection_repo.sync_rules(conn, [r.catalog_entry() for r in self.rules])
        statuses: list[RuleStatus] = []
        for rule in self.rules:
            status = RuleStatus(rule_id=rule.rule_id, name=rule.name, state="ok")
            if not rule.enabled:
                status.state = "disabled"
                statuses.append(status)
                continue
            try:
                result = rule.evaluate(conn, now)
                if result.skipped_reason:
                    status.state, status.detail = "skipped", result.skipped_reason
                else:
                    status.detail = result.note
                for detection in result.detections:
                    last = detection_repo.get_last_fired(conn, detection.dedupe_key)
                    if last is not None and now - last < rule.cooldown:
                        status.suppressed += 1
                        continue
                    self._store(conn, detection, now)
                    status.fired += 1
            except Exception as exc:  # noqa: BLE001 - one broken rule must not stop the rest
                status.state, status.detail = "error", type(exc).__name__
            statuses.append(status)
        return DetectionReport(ran_at=now, rules=statuses)

    @staticmethod
    def _store(conn: sqlite3.Connection, detection, now: datetime) -> None:  # noqa: ANN001
        """Event + cooldown record are written together or not at all."""
        conn.execute("SAVEPOINT detection")
        try:
            events_repo.insert_event(conn, detection.event)
            detection_repo.record_fired(
                conn, detection.dedupe_key, detection.rule_id, detection.event.id, now
            )
        except BaseException:
            conn.execute("ROLLBACK TO detection")
            conn.execute("RELEASE detection")
            raise
        conn.execute("RELEASE detection")
