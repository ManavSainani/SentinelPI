"""Persistence for detection bookkeeping: cooldowns, the port baseline, the rule catalog."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from uuid import UUID

from pydantic import BaseModel

from sentinelpi.collectors.ports import ListeningPort
from sentinelpi.storage import state_repo
from sentinelpi.timeutil import from_db, to_db

BASELINE_META_KEY = "ports.baseline.meta"
COVERAGE_KEY = "ports.coverage"


# ---------------------------------------------------------------- cooldowns
def get_last_fired(conn: sqlite3.Connection, dedupe_key: str) -> datetime | None:
    row = conn.execute(
        "SELECT last_fired_at FROM detection_state WHERE dedupe_key = ?", (dedupe_key,)
    ).fetchone()
    return from_db(row["last_fired_at"]) if row else None


def record_fired(
    conn: sqlite3.Connection, dedupe_key: str, rule_id: str, event_id: UUID, now: datetime
) -> None:
    conn.execute(
        "INSERT INTO detection_state"
        " (dedupe_key, rule_id, last_fired_at, fire_count, last_event_id)"
        " VALUES (?, ?, ?, 1, ?)"
        " ON CONFLICT(dedupe_key) DO UPDATE SET last_fired_at = excluded.last_fired_at,"
        " fire_count = fire_count + 1, last_event_id = excluded.last_event_id",
        (dedupe_key, rule_id, to_db(now), str(event_id)),
    )


def count_state(conn: sqlite3.Connection) -> int:
    return int(conn.execute("SELECT COUNT(*) FROM detection_state").fetchone()[0])


# ---------------------------------------------------------------- rule catalog
def sync_rules(conn: sqlite3.Connection, rules: list[dict[str, object]]) -> None:
    """Mirror the code-defined rules into `detection_rules` (read by the API in Phase 7)."""
    for r in rules:
        conn.execute(
            "INSERT INTO detection_rules (id, name, enabled, severity, threshold_json, description)"
            " VALUES (?, ?, ?, ?, ?, ?)"
            " ON CONFLICT(id) DO UPDATE SET name = excluded.name, enabled = excluded.enabled,"
            " severity = excluded.severity, threshold_json = excluded.threshold_json,"
            " description = excluded.description",
            (
                r["id"],
                r["name"],
                1 if r["enabled"] else 0,
                r["severity"],
                json.dumps(r["thresholds"], separators=(",", ":"), sort_keys=True),
                r["description"],
            ),
        )


# ---------------------------------------------------------------- port baseline
class BaselineMeta(BaseModel):
    captured_at: datetime
    protocols: list[str]  # protocols the baseline was able to observe (e.g. ["tcp"] on macOS)
    count: int


def get_baseline_meta(conn: sqlite3.Connection) -> BaselineMeta | None:
    raw = state_repo.get_state(conn, BASELINE_META_KEY)
    if not raw:
        return None
    try:
        return BaselineMeta.model_validate_json(raw)
    except ValueError:
        return None


def get_baseline_keys(conn: sqlite3.Connection) -> set[tuple[str, int]]:
    return {
        (r["protocol"], r["port"]) for r in conn.execute("SELECT protocol, port FROM port_baseline")
    }


def list_baseline(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT protocol, port, local_address, process_name, captured_at FROM port_baseline"
        " ORDER BY protocol, port"
    ).fetchall()


def replace_baseline(
    conn: sqlite3.Connection,
    ports: list[ListeningPort],
    protocols: list[str],
    captured_at: datetime,
) -> BaselineMeta:
    """Atomically replace the baseline (the caller's transaction commits it)."""
    grouped: dict[tuple[str, int], list[ListeningPort]] = {}
    for p in ports:
        grouped.setdefault((p.protocol, p.port), []).append(p)
    conn.execute("DELETE FROM port_baseline")
    ts = to_db(captured_at)
    for (proto, port), items in sorted(grouped.items()):
        addresses = ",".join(sorted({i.local_address for i in items}))[:128]
        name = next((i.process_name for i in items if i.process_name), None)
        conn.execute(
            "INSERT INTO port_baseline (protocol, port, local_address, process_name, captured_at)"
            " VALUES (?, ?, ?, ?, ?)",
            (proto, port, addresses, name, ts),
        )
    meta = BaselineMeta(captured_at=captured_at, protocols=sorted(protocols), count=len(grouped))
    state_repo.set_state(conn, BASELINE_META_KEY, meta.model_dump_json())
    return meta
