from __future__ import annotations

import sqlite3
from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict, Field

from sentinelpi.api.deps import check_range, get_conn, utc
from sentinelpi.api.errors import ApiError
from sentinelpi.api.pagination import decode_cursor, encode_cursor
from sentinelpi.events import Severity
from sentinelpi.incidents.lifecycle import IncidentNotFoundError, TransitionError, change_status
from sentinelpi.incidents.models import Incident, IncidentStatus, TimelineItem
from sentinelpi.storage import incidents_repo
from sentinelpi.timeutil import to_db

router = APIRouter(tags=["incidents"])


class IncidentPage(BaseModel):
    items: list[Incident]
    total: int
    limit: int
    next_cursor: str | None = None


class IncidentDetail(Incident):
    timeline: list[TimelineItem]
    timeline_limit: int


class StatusChange(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # 'open' is deliberately not accepted: nothing ever goes back to open.
    status: Literal["acknowledged", "resolved", "false_positive"]
    note: Annotated[str | None, Field(max_length=500)] = None


@router.get("/incidents", response_model=IncidentPage)
def list_incidents(
    conn: Annotated[sqlite3.Connection, Depends(get_conn)],
    status: IncidentStatus | None = None,
    severity: Annotated[Severity | None, Query(description="minimum severity")] = None,
    from_: Annotated[datetime | None, Query(alias="from")] = None,
    to: datetime | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
    cursor: Annotated[str | None, Query(max_length=200)] = None,
) -> IncidentPage:
    since, until = utc(from_), utc(to)
    check_range(since, until)
    filters = {"status": status, "min_severity": severity, "since": since, "until": until}
    rows = incidents_repo.list_incidents(
        conn, **filters, after=decode_cursor(cursor), limit=limit + 1
    )
    page, more = rows[:limit], len(rows) > limit
    return IncidentPage(
        items=page,
        total=incidents_repo.count_incidents(conn, **filters),
        limit=limit,
        next_cursor=encode_cursor(to_db(page[-1].last_seen), page[-1].id) if more else None,
    )


def _load(conn: sqlite3.Connection, incident_id: UUID) -> Incident:
    incident = incidents_repo.get_incident(conn, str(incident_id))
    if incident is None:
        raise ApiError(404, "not_found", "No such incident.")
    return incident


@router.get("/incidents/{incident_id}", response_model=IncidentDetail)
def get_incident(
    incident_id: UUID,
    conn: Annotated[sqlite3.Connection, Depends(get_conn)],
    timeline_limit: Annotated[int, Query(ge=1, le=500)] = 200,
) -> IncidentDetail:
    incident = _load(conn, incident_id)
    timeline = incidents_repo.get_timeline(conn, incident.id, limit=timeline_limit)
    return IncidentDetail(**incident.model_dump(), timeline=timeline, timeline_limit=timeline_limit)


@router.patch("/incidents/{incident_id}", response_model=Incident)
def update_incident(
    incident_id: UUID,
    body: StatusChange,
    conn: Annotated[sqlite3.Connection, Depends(get_conn)],
) -> Incident:
    try:
        return change_status(
            conn, str(incident_id), IncidentStatus(body.status), note=body.note, actor="user"
        )
    except IncidentNotFoundError:
        raise ApiError(404, "not_found", "No such incident.") from None
    except TransitionError as exc:
        raise ApiError(409, "invalid_transition", str(exc)) from None
