from __future__ import annotations

import ipaddress
import sqlite3
from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from sentinelpi.api.deps import check_range, get_conn, utc
from sentinelpi.api.errors import ApiError
from sentinelpi.api.pagination import decode_cursor, encode_cursor
from sentinelpi.events import Event, EventSource, Severity
from sentinelpi.storage import events_repo
from sentinelpi.timeutil import to_db

router = APIRouter(tags=["events"])


class EventPage(BaseModel):
    items: list[Event]
    total: int
    limit: int
    next_cursor: str | None = None


@router.get("/events", response_model=EventPage)
def list_events(
    conn: Annotated[sqlite3.Connection, Depends(get_conn)],
    severity: Annotated[Severity | None, Query(description="minimum severity")] = None,
    event_type: Annotated[str | None, Query(alias="type", max_length=64)] = None,
    source: EventSource | None = None,
    source_ip: Annotated[str | None, Query(max_length=45)] = None,
    from_: Annotated[datetime | None, Query(alias="from")] = None,
    to: datetime | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    cursor: Annotated[str | None, Query(max_length=200)] = None,
) -> EventPage:
    since, until = utc(from_), utc(to)
    check_range(since, until)
    if source_ip is not None:
        try:
            source_ip = str(ipaddress.ip_address(source_ip.strip()))
        except ValueError:
            raise ApiError(400, "bad_ip", "source_ip must be an IPv4 or IPv6 address.") from None
    filters = {
        "since": since,
        "until": until,
        "source": source,
        "min_severity": severity,
        "event_type": event_type,
        "source_ip": source_ip,
    }
    after = decode_cursor(cursor)
    rows = events_repo.list_events(conn, **filters, after=after, limit=limit + 1)
    page, more = rows[:limit], len(rows) > limit
    return EventPage(
        items=page,
        total=events_repo.count_filtered(conn, **filters),
        limit=limit,
        next_cursor=encode_cursor(to_db(page[-1].timestamp), str(page[-1].id)) if more else None,
    )


@router.get("/events/{event_id}", response_model=Event)
def get_event(event_id: UUID, conn: Annotated[sqlite3.Connection, Depends(get_conn)]) -> Event:
    event = events_repo.get_event(conn, event_id)
    if event is None:
        raise ApiError(404, "not_found", "No such event.")
    return event
