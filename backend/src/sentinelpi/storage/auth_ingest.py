"""Poll auth logs and store the resulting events plus the new read cursor atomically."""

from __future__ import annotations

import sqlite3
from datetime import datetime

from pydantic import BaseModel

from sentinelpi.collectors.auth_logs import AuthLogCollector
from sentinelpi.collectors.base import CollectorState
from sentinelpi.storage import events_repo, state_repo

_PREFIX = "auth.cursor."


class AuthIngestReport(BaseModel):
    state: CollectorState
    detail: str | None = None
    source: str | None = None
    entries_read: int = 0
    events_parsed: int = 0
    events_stored: int = 0  # lower than parsed if some were already stored
    ignored: int = 0
    malformed: int = 0


def poll_auth_logs(
    conn: sqlite3.Connection, collector: AuthLogCollector, now: datetime | None = None
) -> AuthIngestReport:
    """The caller's transaction (Database.session) commits events and cursor together, so a
    crash can neither lose events nor read them twice."""
    cursors = {}
    for name in collector.source_names:
        value = state_repo.get_state(conn, _PREFIX + name)
        if value:
            cursors[name] = value

    poll = collector.poll(cursors, now)
    status, batch = poll.result.status, poll.result.data
    report = AuthIngestReport(state=status.state, detail=status.detail)
    if batch is None:
        return report  # nothing readable: leave cursors untouched

    report.source = batch.source
    report.entries_read = batch.entries_read
    report.events_parsed = len(batch.events)
    report.ignored, report.malformed = batch.ignored, batch.malformed
    if batch.events:
        report.events_stored = events_repo.insert_events(conn, batch.events, ignore_duplicates=True)
    for name, cursor in poll.cursors.items():
        if cursors.get(name) != cursor:
            state_repo.set_state(conn, _PREFIX + name, cursor)
    return report
