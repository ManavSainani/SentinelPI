"""Event persistence. All SQL is parameterized; filter values never reach the SQL text."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable
from datetime import datetime
from uuid import UUID

from sentinelpi.events import Event, EventSource, Severity, severities_at_least
from sentinelpi.timeutil import from_db, to_db

MAX_LIMIT = 500
_COLUMNS = (
    "id, timestamp, source, event_type, severity, summary, source_ip, username,"
    " process_name, host, metadata_json"
)


def _params(e: Event) -> tuple[object, ...]:
    return (
        str(e.id),
        to_db(e.timestamp),
        e.source.value,
        e.event_type,
        e.severity.value,
        e.summary,
        e.source_ip,
        e.username,
        e.process_name,
        e.host,
        json.dumps(e.metadata, separators=(",", ":")),
    )


def _to_event(row: sqlite3.Row) -> Event:
    try:
        metadata = json.loads(row["metadata_json"])
        if not isinstance(metadata, dict):
            metadata = {}
    except ValueError:  # a corrupted row must not break listings
        metadata = {}
    return Event(
        id=UUID(row["id"]),
        timestamp=from_db(row["timestamp"]),
        source=EventSource(row["source"]),
        event_type=row["event_type"],
        severity=Severity(row["severity"]),
        summary=row["summary"],
        source_ip=row["source_ip"],
        username=row["username"],
        process_name=row["process_name"],
        host=row["host"],
        metadata=metadata,
    )


def insert_event(conn: sqlite3.Connection, event: Event) -> None:
    conn.execute(f"INSERT INTO events ({_COLUMNS}) VALUES (?,?,?,?,?,?,?,?,?,?,?)", _params(event))


def insert_events(
    conn: sqlite3.Connection, events: Iterable[Event], *, ignore_duplicates: bool = False
) -> int:
    """Insert events; returns how many rows were actually stored.

    With ignore_duplicates=True, events whose id already exists are skipped (used for log
    ingestion, where ids are deterministic so re-reading a log entry is harmless).
    """
    verb = "INSERT OR IGNORE" if ignore_duplicates else "INSERT"
    cur = conn.executemany(
        f"{verb} INTO events ({_COLUMNS}) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        [_params(e) for e in events],
    )
    return cur.rowcount


def get_event(conn: sqlite3.Connection, event_id: UUID | str) -> Event | None:
    row = conn.execute(f"SELECT {_COLUMNS} FROM events WHERE id = ?", (str(event_id),)).fetchone()
    return _to_event(row) if row else None


def count_events(conn: sqlite3.Connection) -> int:
    return int(conn.execute("SELECT COUNT(*) FROM events").fetchone()[0])


def _filters(
    since: datetime | None,
    until: datetime | None,
    source: EventSource | None,
    min_severity: Severity | None,
    event_type: str | None,
    source_ip: str | None,
) -> tuple[list[str], list[object]]:
    where: list[str] = []
    args: list[object] = []
    if since is not None:
        where.append("timestamp >= ?")
        args.append(to_db(since))
    if until is not None:
        where.append("timestamp < ?")
        args.append(to_db(until))
    if source is not None:
        where.append("source = ?")
        args.append(source.value)
    if min_severity is not None:
        levels = severities_at_least(min_severity)
        where.append(f"severity IN ({','.join('?' * len(levels))})")
        args.extend(s.value for s in levels)
    if event_type is not None:
        where.append("event_type = ?")
        args.append(event_type)
    if source_ip is not None:
        where.append("source_ip = ?")
        args.append(source_ip)
    return where, args


def list_events(
    conn: sqlite3.Connection,
    *,
    since: datetime | None = None,  # inclusive
    until: datetime | None = None,  # exclusive
    source: EventSource | None = None,
    min_severity: Severity | None = None,
    event_type: str | None = None,
    source_ip: str | None = None,
    after: tuple[str, str] | None = None,  # keyset cursor: (timestamp_db, id) of the last row seen
    limit: int = 100,
) -> list[Event]:
    """Newest first, always bounded (limit is clamped to 1..MAX_LIMIT). `after` continues a
    previous page without skipping or repeating rows even while new events arrive."""
    where, args = _filters(since, until, source, min_severity, event_type, source_ip)
    if after is not None:
        where.append("(timestamp < ? OR (timestamp = ? AND id < ?))")
        args.extend([after[0], after[0], after[1]])
    clause = f"WHERE {' AND '.join(where)}" if where else ""
    args.append(max(1, min(int(limit), MAX_LIMIT)))
    rows = conn.execute(
        f"SELECT {_COLUMNS} FROM events {clause} ORDER BY timestamp DESC, id DESC LIMIT ?", args
    ).fetchall()
    return [_to_event(r) for r in rows]


def count_filtered(
    conn: sqlite3.Connection,
    *,
    since: datetime | None = None,
    until: datetime | None = None,
    source: EventSource | None = None,
    min_severity: Severity | None = None,
    event_type: str | None = None,
    source_ip: str | None = None,
) -> int:
    where, args = _filters(since, until, source, min_severity, event_type, source_ip)
    clause = f"WHERE {' AND '.join(where)}" if where else ""
    return int(conn.execute(f"SELECT COUNT(*) FROM events {clause}", args).fetchone()[0])


def list_events_unattached_detections(
    conn: sqlite3.Connection, *, since: datetime, limit: int = 500
) -> list[Event]:
    """Detection events (`detection.*`) that belong to no incident yet, oldest first."""
    rows = conn.execute(
        f"SELECT {_COLUMNS} FROM events WHERE event_type LIKE 'detection.%'"
        " AND incident_id IS NULL AND timestamp >= ?"
        " AND id NOT IN (SELECT event_id FROM incident_events)"
        " ORDER BY timestamp ASC, id ASC LIMIT ?",
        (to_db(since), max(1, min(int(limit), MAX_LIMIT * 10))),
    ).fetchall()
    return [_to_event(r) for r in rows]
