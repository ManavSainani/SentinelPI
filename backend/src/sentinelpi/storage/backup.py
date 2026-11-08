"""Backup and restore of the SQLite database.

A backup uses SQLite's online backup API, so it is consistent even while the monitor is
writing. A restore is deliberately cautious: it verifies the file first, refuses a database
from a newer SentinelPI, and keeps the database it replaces.
"""

from __future__ import annotations

import contextlib
import os
import sqlite3
from pathlib import Path

from sentinelpi.storage.migrations import load_migrations
from sentinelpi.timeutil import utc_now


class BackupError(RuntimeError):
    pass


def _check(path: Path) -> int:
    """Return the schema version of a SentinelPI database, or raise BackupError."""
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    except sqlite3.Error as exc:
        raise BackupError(f"cannot open {path}: {exc}") from exc
    try:
        if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise BackupError(f"{path} failed the SQLite integrity check")
        version = conn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0]
    except sqlite3.Error as exc:
        raise BackupError(f"{path} is not a SentinelPI database ({exc})") from exc
    finally:
        conn.close()
    if version is None:
        raise BackupError(f"{path} has no schema version; not a SentinelPI database")
    return int(version)


def _copy(src: Path, dest: Path) -> None:
    source = sqlite3.connect(f"file:{src}?mode=ro", uri=True)
    target = sqlite3.connect(dest)
    try:
        source.backup(target)
    finally:
        target.close()
        source.close()
    with contextlib.suppress(OSError):
        os.chmod(dest, 0o600)


def backup_database(src: Path, dest: Path) -> int:
    """Write a verified copy of `src` to `dest`; returns its schema version."""
    if not src.exists():
        raise BackupError(f"database not found: {src}")
    if dest.exists():
        raise BackupError(f"{dest} already exists; choose a new file name")
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        _copy(src, dest)
        return _check(dest)
    except (sqlite3.Error, BackupError):
        dest.unlink(missing_ok=True)
        raise


def restore_database(backup: Path, dest: Path, *, replace: bool = False) -> Path | None:
    """Replace `dest` with `backup`. Returns where the old database was kept, if any.

    Stop the services first: a running monitor would keep writing to the old file.
    """
    version = _check(backup)
    newest = len(load_migrations())
    if version > newest:
        raise BackupError(
            f"backup is schema version {version} but this install only knows {newest}; "
            "upgrade SentinelPI first"
        )
    kept: Path | None = None
    if dest.exists():
        if not replace:
            raise BackupError(f"{dest} exists; pass --replace to swap it (the old one is kept)")
        kept = dest.with_name(f"{dest.name}.before-restore-{utc_now():%Y%m%dT%H%M%SZ}")
        _copy(dest, kept)  # through SQLite, so anything still in the WAL file is included
        dest.unlink()
    for suffix in ("-wal", "-shm"):  # stale journal files must never meet the restored file
        Path(f"{dest}{suffix}").unlink(missing_ok=True)
    dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _copy(backup, dest)
    _check(dest)
    return kept
