"""Small key/value store for collector bookkeeping (e.g. log read cursors)."""

from __future__ import annotations

import re
import sqlite3

from sentinelpi.timeutil import to_db, utc_now

_KEY = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
MAX_VALUE = 1024


def get_state(conn: sqlite3.Connection, key: str) -> str | None:
    row = conn.execute("SELECT value FROM collector_state WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else None


def set_state(conn: sqlite3.Connection, key: str, value: str) -> None:
    if not _KEY.match(key) or len(value) > MAX_VALUE:
        raise ValueError("invalid collector state key or value")
    conn.execute(
        "INSERT INTO collector_state (key, value, updated_at) VALUES (?, ?, ?)"
        " ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
        (key, value, to_db(utc_now())),
    )
