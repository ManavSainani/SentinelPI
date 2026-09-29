"""Retention: age-based pruning plus a database size target.

Rules (from the spec):
  * High-volume data (metrics, process/port snapshots) is pruned sooner than events.
  * Evidence is kept for as long as its incident is kept. Unresolved (open/acknowledged)
    incidents and their events are NEVER deleted automatically, not even for the size target.
  * Resolved / false-positive incidents expire `incident_days` after their last update.
  * If the DB still exceeds the size target, the oldest high-volume data goes first, then the
    oldest unprotected events. If protected data alone exceeds the target we report it
    (`size_target_met=False`) instead of deleting evidence.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta

from pydantic import BaseModel, Field

from sentinelpi.config import RetentionSettings
from sentinelpi.timeutil import to_db, utc_now

# (table, time column). Constants only: these are interpolated into SQL text.
_SIZE_CAP_ORDER = [
    ("process_snapshots", "timestamp"),
    ("listening_ports", "observed_at"),
    ("system_metrics", "timestamp"),
]
_UNPROTECTED = "incident_id IS NULL AND id NOT IN (SELECT event_id FROM incident_events)"


class RetentionReport(BaseModel):
    ran_at: datetime
    deleted: dict[str, int] = Field(default_factory=dict)
    size_cap_deleted: dict[str, int] = Field(default_factory=dict)
    protected_old_events: int = 0  # past the window but kept because a kept incident owns them
    used_bytes_before: int = 0
    used_bytes_after: int = 0
    size_target_met: bool = True


def db_used_bytes(conn: sqlite3.Connection) -> int:
    """Bytes in use by live pages (freed pages don't count), so pruning shows immediately."""
    page_count = conn.execute("PRAGMA page_count").fetchone()[0]
    free = conn.execute("PRAGMA freelist_count").fetchone()[0]
    page_size = conn.execute("PRAGMA page_size").fetchone()[0]
    return int((page_count - free) * page_size)


def _delete_oldest_batches(
    conn: sqlite3.Connection, table: str, time_col: str, where: str, max_bytes: int
) -> int:
    deleted = 0
    while db_used_bytes(conn) > max_bytes:
        count = conn.execute(f"SELECT COUNT(*) FROM {table} WHERE {where}").fetchone()[0]
        if count == 0:
            break
        batch = max(1, count // 10)
        cur = conn.execute(
            f"DELETE FROM {table} WHERE id IN (SELECT id FROM {table} WHERE {where}"
            f" ORDER BY {time_col} ASC, id ASC LIMIT ?)",
            (batch,),
        )
        deleted += cur.rowcount
    return deleted


def run_retention(
    conn: sqlite3.Connection,
    policy: RetentionSettings,
    *,
    now: datetime | None = None,
    max_db_bytes: int | None = None,
) -> RetentionReport:
    now = now or utc_now()
    max_bytes = max_db_bytes if max_db_bytes is not None else policy.max_db_mb * 1024 * 1024
    report = RetentionReport(ran_at=now, used_bytes_before=db_used_bytes(conn))

    def cutoff(days: int) -> str:
        return to_db(now - timedelta(days=days))

    def delete(label: str, sql: str, args: tuple[object, ...]) -> None:
        report.deleted[label] = conn.execute(sql, args).rowcount

    delete(
        "system_metrics",
        "DELETE FROM system_metrics WHERE timestamp < ?",
        (cutoff(policy.metrics_days),),
    )
    delete(
        "process_snapshots",
        "DELETE FROM process_snapshots WHERE timestamp < ?",
        (cutoff(policy.snapshot_days),),
    )
    delete(
        "listening_ports",
        "DELETE FROM listening_ports WHERE observed_at < ?",
        (cutoff(policy.snapshot_days),),
    )
    # Expired incidents first: this releases their events (FK: incident_id -> NULL,
    # incident_events rows cascade), which the event sweep below may then remove.
    delete(
        "incidents",
        "DELETE FROM incidents WHERE status IN ('resolved','false_positive') AND updated_at < ?",
        (cutoff(policy.incident_days),),
    )
    delete(
        "events",
        f"DELETE FROM events WHERE timestamp < ? AND {_UNPROTECTED}",
        (cutoff(policy.events_days),),
    )
    report.protected_old_events = conn.execute(
        f"SELECT COUNT(*) FROM events WHERE timestamp < ? AND NOT ({_UNPROTECTED})",
        (cutoff(policy.events_days),),
    ).fetchone()[0]

    if db_used_bytes(conn) > max_bytes:
        for table, time_col in _SIZE_CAP_ORDER:
            n = _delete_oldest_batches(conn, table, time_col, "1=1", max_bytes)
            if n:
                report.size_cap_deleted[table] = n
        n = _delete_oldest_batches(conn, "events", "timestamp", _UNPROTECTED, max_bytes)
        if n:
            report.size_cap_deleted["events"] = n

    conn.commit()
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
    conn.execute("PRAGMA incremental_vacuum").fetchall()  # return freed pages to the OS
    report.used_bytes_after = db_used_bytes(conn)
    report.size_target_met = report.used_bytes_after <= max_bytes
    return report
