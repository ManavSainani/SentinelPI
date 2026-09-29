"""UTC time helpers. Everything stored or returned is timezone-aware UTC.

The DB format is fixed-width ISO-8601 ("2026-09-28T22:58:04.847224Z") so that plain text
comparison in SQL is also chronological comparison.
"""

from __future__ import annotations

from datetime import UTC, datetime

_DB_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"


def utc_now() -> datetime:
    return datetime.now(UTC)


def to_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        raise ValueError("timestamp must be timezone-aware")
    return dt.astimezone(UTC)


def to_db(dt: datetime) -> str:
    return to_utc(dt).strftime(_DB_FORMAT)


def from_db(text: str) -> datetime:
    return datetime.strptime(text, _DB_FORMAT).replace(tzinfo=UTC)
