"""User-driven status changes. Every change is audited with a timestamp, the actor, and an
optional note. Terminal states (resolved, false_positive) are final: if the same activity
recurs it opens a new incident, so history is never rewritten.

    open -> acknowledged -> resolved
      |          |
      +----------+--------> false_positive    (also open -> resolved directly)
"""

from __future__ import annotations

import sqlite3
from datetime import datetime

from sentinelpi.incidents.models import Incident, IncidentStatus
from sentinelpi.safety import clean_text
from sentinelpi.storage import incidents_repo
from sentinelpi.timeutil import utc_now

MAX_NOTE = 500

ALLOWED: dict[IncidentStatus, frozenset[IncidentStatus]] = {
    IncidentStatus.OPEN: frozenset(
        {IncidentStatus.ACKNOWLEDGED, IncidentStatus.RESOLVED, IncidentStatus.FALSE_POSITIVE}
    ),
    IncidentStatus.ACKNOWLEDGED: frozenset(
        {IncidentStatus.RESOLVED, IncidentStatus.FALSE_POSITIVE}
    ),
    IncidentStatus.RESOLVED: frozenset(),
    IncidentStatus.FALSE_POSITIVE: frozenset(),
}


class IncidentNotFoundError(LookupError):
    pass


class TransitionError(ValueError):
    pass


def change_status(
    conn: sqlite3.Connection,
    incident_id: str,
    new_status: IncidentStatus,
    *,
    note: str | None = None,
    actor: str = "user",
    now: datetime | None = None,
) -> Incident:
    now = now or utc_now()
    incident = incidents_repo.get_incident(conn, incident_id)
    if incident is None:
        raise IncidentNotFoundError(incident_id)
    if new_status not in ALLOWED[incident.status]:
        raise TransitionError(f"cannot change an incident from {incident.status} to {new_status}")
    cleaned = clean_text(note, MAX_NOTE) if note else None
    conn.execute("SAVEPOINT status_change")
    try:
        applied = incidents_repo.set_status(
            conn, incident_id, new_status, cleaned or None, now, expected=incident.status
        )
        if not applied:
            raise TransitionError("the incident changed while updating; reload and try again")
        incidents_repo.add_audit(
            conn,
            incident_id,
            now,
            "status_changed",
            actor,
            from_status=incident.status,
            to_status=new_status,
            note=cleaned or None,
        )
    except BaseException:
        conn.execute("ROLLBACK TO status_change")
        conn.execute("RELEASE status_change")
        raise
    conn.execute("RELEASE status_change")
    updated = incidents_repo.get_incident(conn, incident_id)
    assert updated is not None
    return updated
