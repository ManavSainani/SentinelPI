"""Incident persistence. All SQL is parameterized; only constants are interpolated."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from sentinelpi.events import Severity, severities_at_least
from sentinelpi.incidents.models import Incident, IncidentStatus, TimelineItem
from sentinelpi.timeutil import from_db, to_db

MAX_LIMIT = 500
_ACTIVE = ("open", "acknowledged")
_SELECT = (
    "SELECT i.id, i.title, i.description, i.severity, i.risk_score, i.status, i.host,"
    " i.source_ip, i.rule_ids_json, i.risk_breakdown_json, i.first_seen, i.last_seen,"
    " i.created_at, i.updated_at, i.resolution_note,"
    " (SELECT COUNT(*) FROM incident_events ie WHERE ie.incident_id = i.id) AS evidence_count"
    " FROM incidents i"
)


class AmbiguousIdError(ValueError):
    pass


def _loads(text: str, default: Any) -> Any:
    try:
        value = json.loads(text)
    except ValueError:
        return default
    return value if isinstance(value, type(default)) else default


def _to_incident(row: sqlite3.Row) -> Incident:
    return Incident(
        id=row["id"],
        title=row["title"],
        description=row["description"],
        severity=Severity(row["severity"]),
        risk_score=row["risk_score"],
        status=IncidentStatus(row["status"]),
        host=row["host"],
        source_ip=row["source_ip"],
        rule_ids=_loads(row["rule_ids_json"], []),
        risk_breakdown=_loads(row["risk_breakdown_json"], []),
        first_seen=from_db(row["first_seen"]),
        last_seen=from_db(row["last_seen"]),
        created_at=from_db(row["created_at"]),
        updated_at=from_db(row["updated_at"]),
        resolution_note=row["resolution_note"],
        evidence_count=row["evidence_count"],
    )


def _dumps(value: object) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


# ---------------------------------------------------------------- reads
def get_incident(conn: sqlite3.Connection, incident_id: str) -> Incident | None:
    row = conn.execute(f"{_SELECT} WHERE i.id = ?", (incident_id,)).fetchone()
    return _to_incident(row) if row else None


def resolve_id(conn: sqlite3.Connection, prefix: str) -> str | None:
    """Accept a full id or a unique prefix (what the CLI prints). None if nothing matches."""
    prefix = prefix.strip().lower()
    if not prefix or not all(c in "0123456789abcdef-" for c in prefix):
        return None
    rows = conn.execute(
        "SELECT id FROM incidents WHERE id LIKE ? ESCAPE '\\' LIMIT 2", (prefix + "%",)
    ).fetchall()
    if len(rows) > 1:
        raise AmbiguousIdError(f"'{prefix}' matches more than one incident; type more characters")
    return rows[0]["id"] if rows else None


def _incident_filters(
    status: IncidentStatus | None,
    min_severity: Severity | None,
    since: datetime | None,
    until: datetime | None,
) -> tuple[list[str], list[object]]:
    where: list[str] = []
    args: list[object] = []
    if status is not None:
        where.append("i.status = ?")
        args.append(status.value)
    if min_severity is not None:
        levels = severities_at_least(min_severity)
        where.append(f"i.severity IN ({','.join('?' * len(levels))})")
        args.extend(s.value for s in levels)
    if since is not None:
        where.append("i.last_seen >= ?")
        args.append(to_db(since))
    if until is not None:
        where.append("i.last_seen < ?")
        args.append(to_db(until))
    return where, args


def list_incidents(
    conn: sqlite3.Connection,
    *,
    status: IncidentStatus | None = None,
    min_severity: Severity | None = None,
    since: datetime | None = None,  # on last_seen, inclusive
    until: datetime | None = None,  # on last_seen, exclusive
    after: tuple[str, str] | None = None,  # keyset cursor: (last_seen_db, id)
    limit: int = 50,
) -> list[Incident]:
    """Most recently active first, always bounded."""
    where, args = _incident_filters(status, min_severity, since, until)
    if after is not None:
        where.append("(i.last_seen < ? OR (i.last_seen = ? AND i.id < ?))")
        args.extend([after[0], after[0], after[1]])
    clause = f"WHERE {' AND '.join(where)}" if where else ""
    args.append(max(1, min(int(limit), MAX_LIMIT)))
    rows = conn.execute(
        f"{_SELECT} {clause} ORDER BY i.last_seen DESC, i.id DESC LIMIT ?", args
    ).fetchall()
    return [_to_incident(r) for r in rows]


def count_incidents(
    conn: sqlite3.Connection,
    *,
    status: IncidentStatus | None = None,
    min_severity: Severity | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
) -> int:
    where, args = _incident_filters(status, min_severity, since, until)
    clause = f"WHERE {' AND '.join(where)}" if where else ""
    return int(conn.execute(f"SELECT COUNT(*) FROM incidents i {clause}", args).fetchone()[0])


def count_by_status(conn: sqlite3.Connection) -> dict[str, int]:
    counts = {s.value: 0 for s in IncidentStatus}
    for r in conn.execute("SELECT status, COUNT(*) AS n FROM incidents GROUP BY status"):
        counts[r["status"]] = r["n"]
    return counts


def find_open_match(
    conn: sqlite3.Connection,
    *,
    host: str,
    source_ip: str | None,
    ts: datetime,
    window: timedelta,
    max_age: timedelta,
) -> Incident | None:
    """The active incident for the same host and the same subject (IP, or None for
    host-local) whose span is within `window` of `ts`, and which is not older than
    `max_age` at `ts` (so a long-running condition eventually starts a fresh incident)."""
    row = conn.execute(
        f"{_SELECT} WHERE i.host = ? AND i.source_ip IS ? AND i.status IN (?, ?)"
        " AND i.last_seen >= ? AND i.first_seen <= ? AND i.first_seen >= ?"
        " ORDER BY i.last_seen DESC, i.id DESC LIMIT 1",
        (host, source_ip, *_ACTIVE, to_db(ts - window), to_db(ts + window), to_db(ts - max_age)),
    ).fetchone()
    return _to_incident(row) if row else None


def attached_detection_rule_ids(conn: sqlite3.Connection, incident_id: str) -> list[str]:
    """Rule id of every detection event attached to an incident (one entry per detection)."""
    rows = conn.execute(
        "SELECT e.metadata_json FROM incident_events ie JOIN events e ON e.id = ie.event_id"
        " WHERE ie.incident_id = ? AND e.event_type LIKE 'detection.%'",
        (incident_id,),
    ).fetchall()
    found: list[str] = []
    for r in rows:
        rule_id = _loads(r["metadata_json"], {}).get("rule_id")
        if isinstance(rule_id, str):
            found.append(rule_id)
    return sorted(found)


def attached_time_span(conn: sqlite3.Connection, incident_id: str) -> tuple[datetime, datetime]:
    """Earliest and latest timestamp among everything attached (evidence included)."""
    row = conn.execute(
        "SELECT MIN(e.timestamp) AS lo, MAX(e.timestamp) AS hi FROM incident_events ie"
        " JOIN events e ON e.id = ie.event_id WHERE ie.incident_id = ?",
        (incident_id,),
    ).fetchone()
    return from_db(row["lo"]), from_db(row["hi"])


def attached_max_severity(conn: sqlite3.Connection, incident_id: str) -> Severity:
    rows = conn.execute(
        "SELECT DISTINCT e.severity FROM incident_events ie JOIN events e ON e.id = ie.event_id"
        " WHERE ie.incident_id = ? AND e.event_type LIKE 'detection.%'",
        (incident_id,),
    ).fetchall()
    return max((Severity(r["severity"]) for r in rows), key=lambda s: s.rank, default=Severity.LOW)


# ---------------------------------------------------------------- writes
def create_incident(conn: sqlite3.Connection, inc: Incident) -> None:
    conn.execute(
        "INSERT INTO incidents (id, title, description, severity, risk_score, status, host,"
        " source_ip, rule_ids_json, risk_breakdown_json, first_seen, last_seen, created_at,"
        " updated_at, resolution_note) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            inc.id,
            inc.title,
            inc.description,
            inc.severity.value,
            inc.risk_score,
            inc.status.value,
            inc.host,
            inc.source_ip,
            _dumps(inc.rule_ids),
            _dumps(inc.risk_breakdown),
            to_db(inc.first_seen),
            to_db(inc.last_seen),
            to_db(inc.created_at),
            to_db(inc.updated_at),
            inc.resolution_note,
        ),
    )


def attach_event(conn: sqlite3.Connection, incident_id: str, event_id: UUID | str) -> bool:
    """Link an existing event to an incident. Returns False if it was already linked or the
    event no longer exists. The event's primary `incident_id` is set only if still empty, so
    an event that supports several incidents keeps one primary owner."""
    cur = conn.execute(
        "INSERT OR IGNORE INTO incident_events (incident_id, event_id)"
        " SELECT ?, id FROM events WHERE id = ?",
        (incident_id, str(event_id)),
    )
    inserted = cur.rowcount == 1
    conn.execute(
        "UPDATE events SET incident_id = ? WHERE id = ? AND incident_id IS NULL",
        (incident_id, str(event_id)),
    )
    return inserted


def update_derived(
    conn: sqlite3.Connection,
    incident_id: str,
    *,
    title: str,
    description: str,
    severity: Severity,
    risk_score: int,
    rule_ids: list[str],
    breakdown: list[dict[str, Any]],
    first_seen: datetime,
    last_seen: datetime,
    now: datetime,
) -> None:
    conn.execute(
        "UPDATE incidents SET title = ?, description = ?, severity = ?, risk_score = ?,"
        " rule_ids_json = ?, risk_breakdown_json = ?, first_seen = ?, last_seen = ?,"
        " updated_at = ? WHERE id = ?",
        (
            title,
            description,
            severity.value,
            risk_score,
            _dumps(rule_ids),
            _dumps(breakdown),
            to_db(first_seen),
            to_db(last_seen),
            to_db(now),
            incident_id,
        ),
    )


def set_status(
    conn: sqlite3.Connection,
    incident_id: str,
    status: IncidentStatus,
    note: str | None,
    now: datetime,
    *,
    expected: IncidentStatus,
) -> bool:
    """Compare-and-swap: only changes the row if it is still in `expected` status, so two
    writers (CLI and API, say) cannot both apply a transition. Returns whether it applied."""
    cur = conn.execute(
        "UPDATE incidents SET status = ?, resolution_note = COALESCE(?, resolution_note),"
        " updated_at = ? WHERE id = ? AND status = ?",
        (status.value, note, to_db(now), incident_id, expected.value),
    )
    return cur.rowcount == 1


def add_audit(
    conn: sqlite3.Connection,
    incident_id: str,
    at: datetime,
    kind: str,
    actor: str,
    *,
    from_status: IncidentStatus | None = None,
    to_status: IncidentStatus | None = None,
    note: str | None = None,
    detail: str | None = None,
) -> None:
    conn.execute(
        "INSERT INTO incident_audit (incident_id, at, kind, actor, from_status, to_status,"
        " note, detail) VALUES (?,?,?,?,?,?,?,?)",
        (
            incident_id,
            to_db(at),
            kind,
            actor,
            from_status.value if from_status else None,
            to_status.value if to_status else None,
            note,
            detail,
        ),
    )


# ---------------------------------------------------------------- timeline
def get_timeline(
    conn: sqlite3.Connection, incident_id: str, limit: int = 500
) -> list[TimelineItem]:
    """Evidence events and audit entries merged oldest-first. Bounded: at most `limit` of each."""
    limit = max(1, min(int(limit), MAX_LIMIT))
    items: list[TimelineItem] = []
    for r in conn.execute(
        "SELECT e.id, e.timestamp, e.event_type, e.severity, e.summary FROM incident_events ie"
        " JOIN events e ON e.id = ie.event_id WHERE ie.incident_id = ?"
        " ORDER BY e.timestamp ASC, e.id ASC LIMIT ?",
        (incident_id, limit),
    ):
        items.append(
            TimelineItem(
                at=from_db(r["timestamp"]),
                kind="event",
                event_id=r["id"],
                event_type=r["event_type"],
                severity=Severity(r["severity"]),
                summary=r["summary"],
            )
        )
    for r in conn.execute(
        "SELECT at, kind, actor, from_status, to_status, note, detail FROM incident_audit"
        " WHERE incident_id = ? ORDER BY id ASC LIMIT ?",
        (incident_id, limit),
    ):
        items.append(
            TimelineItem(
                at=from_db(r["at"]),
                kind="audit",
                audit_kind=r["kind"],
                actor=r["actor"],
                from_status=r["from_status"],
                to_status=r["to_status"],
                note=r["note"],
                summary=r["detail"],
            )
        )
    # Stable sort: at equal times, evidence (added first) precedes the audit entry about it.
    items.sort(key=lambda i: i.at)
    return items
