"""SP-004: a running process whose name is on the configurable watchlist.

Matching is by process name only, case-insensitive and exact. Command lines are never
collected, so the "redacted command" in the evidence is just the sanitized process name.
The collector keeps watchlist matches even when they are outside the top-N by load.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta
from typing import Any

from sentinelpi.collectors.processes import ProcessInfo
from sentinelpi.config import ScoringSettings
from sentinelpi.config import WatchlistRule as Config
from sentinelpi.detection.base import Detection, Rule, RuleResult
from sentinelpi.detection.scoring import rule_weight
from sentinelpi.events import Event, EventSource, Severity
from sentinelpi.storage import telemetry_repo
from sentinelpi.timeutil import to_db
from sentinelpi.watchlist import is_watchlisted, normalize_watchlist

MAX_PIDS = 10


class WatchlistRule(Rule):
    rule_id = "SP-004"
    name = "Unexpected process"
    description = "A running process whose name matches the configured watchlist."
    severity = Severity.MEDIUM

    def __init__(self, cfg: Config, scoring: ScoringSettings, max_age: timedelta) -> None:
        self.cfg = cfg
        self._points = rule_weight(self.rule_id, scoring)
        self._max_age = max_age
        self._watch = normalize_watchlist(cfg.process_names)

    @property
    def enabled(self) -> bool:
        return self.cfg.enabled

    @property
    def cooldown(self) -> timedelta:
        return timedelta(minutes=self.cfg.cooldown_minutes)

    def thresholds(self) -> dict[str, Any]:
        return {
            "process_names": self.cfg.process_names,
            "cooldown_minutes": self.cfg.cooldown_minutes,
        }

    def evaluate(self, conn: sqlite3.Connection, now: datetime) -> RuleResult:
        snap = telemetry_repo.latest_process_snapshot(conn)
        if snap is None:
            return RuleResult(skipped_reason="no process snapshot yet")
        observed_at, processes = snap
        if now - observed_at > self._max_age:
            return RuleResult(skipped_reason="latest process snapshot is stale")

        groups: dict[str, list[ProcessInfo]] = {}
        for p in processes:
            if is_watchlisted(p.name, self._watch):
                groups.setdefault(p.name.strip().lower(), []).append(p)

        result = RuleResult()
        for name in sorted(groups):
            result.detections.append(self._detection(name, groups[name], observed_at, now))
        return result

    def _detection(
        self, name: str, procs: list[ProcessInfo], observed_at: datetime, now: datetime
    ) -> Detection:
        users = sorted({p.username for p in procs if p.username})[:5]
        pids = sorted(p.pid for p in procs)
        display = procs[0].name
        metadata: dict[str, Any] = {
            "rule_id": self.rule_id,
            "rule_name": self.name,
            "trigger": "running process name matches the watchlist",
            "explanation": f"A process named '{display}' is running; that name is on the "
            "SentinelPi watchlist.",
            "process_name": display,
            "instances": len(procs),
            "pids": pids[:MAX_PIDS],
            "users": users,
            "max_cpu_percent": round(max(p.cpu_percent for p in procs), 1),
            "max_memory_percent": round(max(p.memory_percent for p in procs), 1),
            "command_redacted": procs[0].command_redacted,
            "command_line_collected": False,
            "observed_at": to_db(observed_at),
            "dedupe_key": f"{self.rule_id}:{name}",
            "risk_points": self._points,
        }
        event = Event(
            timestamp=now,
            source=EventSource.PROCESS_INVENTORY,
            event_type="detection.watchlisted_process",
            severity=self.severity,
            summary=f"SP-004: watchlisted process '{display}' is running",
            process_name=display,
            metadata=metadata,
        )
        return Detection(self.rule_id, f"{self.rule_id}:{name}", event)
