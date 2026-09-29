"""SQLite connection handling.

One short-lived connection per unit of work (`Database.session()`): sqlite3 connections are
not shared across threads, and opening one is cheap. WAL mode lets the API read while the
collector writes.
"""

from __future__ import annotations

import contextlib
import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from sentinelpi.storage.migrations import run_migrations


def connect(path: str | os.PathLike[str]) -> sqlite3.Connection:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    is_new = not p.exists() or p.stat().st_size == 0
    conn = sqlite3.connect(p, timeout=5.0)
    conn.row_factory = sqlite3.Row
    if is_new:
        # Must precede the first table, or the file can never shrink after pruning.
        conn.execute("PRAGMA auto_vacuum = INCREMENTAL")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 5000")
    if is_new:
        with contextlib.suppress(OSError):  # best effort; not supported on every platform
            os.chmod(p, 0o600)  # telemetry is private to the service account
    return conn


class Database:
    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)

    @contextmanager
    def session(self) -> Iterator[sqlite3.Connection]:
        """Commit on success, roll back on any error, always close."""
        conn = connect(self.path)
        try:
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

    def migrate(self) -> list[int]:
        """Apply pending migrations; returns the versions applied (empty if up to date)."""
        with self.session() as conn:
            return run_migrations(conn)
