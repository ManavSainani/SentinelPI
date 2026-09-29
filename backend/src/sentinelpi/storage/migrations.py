"""Forward-only SQL migrations using only the standard library.

Files live in `storage/migration_files/NNNN_name.sql`. Each runs in one transaction together with
its bookkeeping row. Applied migrations are checksummed, so editing an old migration (instead
of adding a new one) is detected and refused. A database newer than this code is refused too.
"""

from __future__ import annotations

import hashlib
import re
import sqlite3
from dataclasses import dataclass
from importlib import resources

from sentinelpi.timeutil import to_db, utc_now

_FILENAME = re.compile(r"^(\d{4})_([a-z0-9_]+)\.sql$")


class MigrationError(RuntimeError):
    pass


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    sql: str
    checksum: str


def load_migrations() -> list[Migration]:
    found: list[Migration] = []
    for entry in (resources.files("sentinelpi.storage") / "migration_files").iterdir():
        match = _FILENAME.match(entry.name)
        if not match:
            continue
        sql = entry.read_text(encoding="utf-8")
        found.append(
            Migration(
                version=int(match.group(1)),
                name=match.group(2),
                sql=sql,
                checksum=hashlib.sha256(sql.encode()).hexdigest(),
            )
        )
    found.sort(key=lambda m: m.version)
    if [m.version for m in found] != list(range(1, len(found) + 1)):
        raise MigrationError("migration versions must be contiguous starting at 0001")
    return found


def _statements(sql: str) -> list[str]:
    statements: list[str] = []
    buffer = ""
    for line in sql.splitlines(keepends=True):
        buffer += line
        if sqlite3.complete_statement(buffer):
            statements.append(buffer.strip())
            buffer = ""
    leftover = [ln for ln in buffer.splitlines() if ln.strip() and not ln.strip().startswith("--")]
    if leftover:
        raise MigrationError("migration ends with an incomplete statement")
    return statements


def run_migrations(conn: sqlite3.Connection) -> list[int]:
    previous_isolation = conn.isolation_level
    conn.isolation_level = None  # we manage transactions explicitly
    try:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations ("
            " version INTEGER PRIMARY KEY, name TEXT NOT NULL,"
            " checksum TEXT NOT NULL, applied_at TEXT NOT NULL)"
        )
        known = {m.version: m for m in load_migrations()}
        applied = {
            r["version"]: r["checksum"]
            for r in conn.execute("SELECT version, checksum FROM schema_migrations")
        }
        if any(v not in known for v in applied):
            raise MigrationError(
                "database schema is newer than this version of SentinelPi; refusing to run"
            )
        for version, checksum in applied.items():
            if known[version].checksum != checksum:
                raise MigrationError(f"migration {version:04d} was modified after being applied")

        done: list[int] = []
        for migration in known.values():
            conn.execute("BEGIN IMMEDIATE")
            try:
                already = conn.execute(
                    "SELECT 1 FROM schema_migrations WHERE version = ?", (migration.version,)
                ).fetchone()
                if already:  # another process applied it while we waited for the lock
                    conn.execute("ROLLBACK")
                    continue
                for statement in _statements(migration.sql):
                    conn.execute(statement)
                conn.execute(
                    "INSERT INTO schema_migrations (version, name, checksum, applied_at)"
                    " VALUES (?, ?, ?, ?)",
                    (migration.version, migration.name, migration.checksum, to_db(utc_now())),
                )
                conn.execute("COMMIT")
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise
            done.append(migration.version)
        return done
    finally:
        conn.isolation_level = previous_isolation
