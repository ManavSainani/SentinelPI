"""Capture the approved listening-port baseline from the latest stored snapshot."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta

from pydantic import BaseModel

from sentinelpi.collectors.ports import ListeningPort
from sentinelpi.storage import detection_repo, state_repo, telemetry_repo
from sentinelpi.timeutil import utc_now

MAX_SNAPSHOT_AGE = timedelta(minutes=10)


class BaselineError(RuntimeError):
    pass


class BaselineCandidate(BaseModel):
    observed_at: datetime
    protocols: list[str]
    ports: list[ListeningPort]


def candidate(conn: sqlite3.Connection, now: datetime | None = None) -> BaselineCandidate:
    """What `capture` would approve right now. Raises BaselineError if it cannot be trusted."""
    now = now or utc_now()
    snap = telemetry_repo.latest_port_snapshot(conn)
    if snap is None:
        raise BaselineError(
            "no port snapshot stored yet; run: python -m sentinelpi.storage collect-once"
        )
    observed_at, ports = snap
    if now - observed_at > MAX_SNAPSHOT_AGE:
        raise BaselineError(
            "the latest port snapshot is more than 10 minutes old; take a fresh one with: "
            "python -m sentinelpi.storage collect-once"
        )
    coverage = state_repo.get_state(conn, detection_repo.COVERAGE_KEY) or "tcp"
    protocols = [p for p in coverage.split(",") if p in {"tcp", "udp"}] or ["tcp"]
    return BaselineCandidate(observed_at=observed_at, protocols=protocols, ports=ports)


def capture(conn: sqlite3.Connection, now: datetime | None = None) -> detection_repo.BaselineMeta:
    c = candidate(conn, now)
    return detection_repo.replace_baseline(conn, c.ports, c.protocols, c.observed_at)
