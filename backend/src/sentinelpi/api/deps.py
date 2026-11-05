from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from datetime import datetime

from fastapi import Request

from sentinelpi.api.errors import ApiError
from sentinelpi.config import Settings
from sentinelpi.storage.db import Database
from sentinelpi.timeutil import to_utc


def get_settings(request: Request) -> Settings:
    return request.app.state.settings


def get_conn(request: Request) -> Iterator[sqlite3.Connection]:
    """One short-lived connection per request; committed on success, rolled back on error."""
    db: Database = request.app.state.db
    with db.session() as conn:
        yield conn


def utc(value: datetime | None) -> datetime | None:
    """Query timestamps must say their timezone ('Z' or an offset): a bare local time is
    ambiguous, and guessing would silently shift the window."""
    if value is None:
        return None
    try:
        return to_utc(value)
    except ValueError:
        raise ApiError(
            400, "bad_timestamp", "Timestamps must include a timezone, e.g. 2026-11-05T12:00:00Z."
        ) from None


def check_range(since: datetime | None, until: datetime | None) -> None:
    if since is not None and until is not None and since >= until:
        raise ApiError(400, "bad_range", "'from' must be earlier than 'to'.")
