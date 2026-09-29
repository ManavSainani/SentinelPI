"""Persistence for metrics, process snapshots and listening-port snapshots."""

from __future__ import annotations

import sqlite3
from datetime import datetime

from sentinelpi.collectors.metrics import MetricsSample
from sentinelpi.collectors.ports import ListeningPort, PortSnapshot
from sentinelpi.collectors.processes import ProcessInfo, ProcessSnapshot
from sentinelpi.timeutil import from_db, to_db

MAX_METRIC_ROWS = 5000
_METRIC_COLS = (
    "timestamp, cpu_percent, memory_percent, disk_percent, temperature_c,"
    " uptime_seconds, net_rx_bytes, net_tx_bytes"
)


def _to_sample(r: sqlite3.Row) -> MetricsSample:
    return MetricsSample(
        timestamp=from_db(r["timestamp"]),
        cpu_percent=r["cpu_percent"],
        memory_percent=r["memory_percent"],
        disk_percent=r["disk_percent"],
        temperature_c=r["temperature_c"],
        uptime_seconds=r["uptime_seconds"],
        net_rx_bytes=r["net_rx_bytes"],
        net_tx_bytes=r["net_tx_bytes"],
    )


def insert_metrics(conn: sqlite3.Connection, s: MetricsSample) -> None:
    insert_metrics_many(conn, [s])


def insert_metrics_many(conn: sqlite3.Connection, samples: list[MetricsSample]) -> int:
    conn.executemany(
        f"INSERT INTO system_metrics ({_METRIC_COLS}) VALUES (?,?,?,?,?,?,?,?)",
        [
            (
                to_db(s.timestamp),
                s.cpu_percent,
                s.memory_percent,
                s.disk_percent,
                s.temperature_c,
                s.uptime_seconds,
                s.net_rx_bytes,
                s.net_tx_bytes,
            )
            for s in samples
        ],
    )
    return len(samples)


def latest_metrics(conn: sqlite3.Connection) -> MetricsSample | None:
    row = conn.execute(
        f"SELECT {_METRIC_COLS} FROM system_metrics ORDER BY timestamp DESC, id DESC LIMIT 1"
    ).fetchone()
    return _to_sample(row) if row else None


def list_metrics(
    conn: sqlite3.Connection,
    *,
    since: datetime | None = None,  # inclusive
    until: datetime | None = None,  # exclusive
    limit: int = 1000,
) -> list[MetricsSample]:
    """The most recent `limit` samples in the window, returned oldest-first (chart order)."""
    where: list[str] = []
    args: list[object] = []
    if since is not None:
        where.append("timestamp >= ?")
        args.append(to_db(since))
    if until is not None:
        where.append("timestamp < ?")
        args.append(to_db(until))
    clause = f"WHERE {' AND '.join(where)}" if where else ""
    args.append(max(1, min(int(limit), MAX_METRIC_ROWS)))
    rows = conn.execute(
        f"SELECT {_METRIC_COLS} FROM system_metrics {clause}"
        " ORDER BY timestamp DESC, id DESC LIMIT ?",
        args,
    ).fetchall()
    return [_to_sample(r) for r in reversed(rows)]


def insert_process_snapshot(conn: sqlite3.Connection, snap: ProcessSnapshot) -> int:
    ts = to_db(snap.timestamp)
    conn.executemany(
        "INSERT INTO process_snapshots"
        " (timestamp, pid, name, username, cpu_percent, memory_percent, command_redacted)"
        " VALUES (?,?,?,?,?,?,?)",
        [
            (ts, p.pid, p.name, p.username, p.cpu_percent, p.memory_percent, p.command_redacted)
            for p in snap.processes
        ],
    )
    return len(snap.processes)


def latest_process_snapshot(conn: sqlite3.Connection) -> tuple[datetime, list[ProcessInfo]] | None:
    latest = conn.execute("SELECT MAX(timestamp) FROM process_snapshots").fetchone()[0]
    if latest is None:
        return None
    rows = conn.execute(
        "SELECT pid, name, username, cpu_percent, memory_percent, command_redacted"
        " FROM process_snapshots WHERE timestamp = ?"
        " ORDER BY (cpu_percent + memory_percent) DESC, pid ASC",
        (latest,),
    ).fetchall()
    return from_db(latest), [
        ProcessInfo(
            pid=r["pid"],
            name=r["name"],
            username=r["username"],
            cpu_percent=r["cpu_percent"],
            memory_percent=r["memory_percent"],
            command_redacted=r["command_redacted"],
        )
        for r in rows
    ]


def insert_port_snapshot(conn: sqlite3.Connection, snap: PortSnapshot) -> int:
    ts = to_db(snap.timestamp)
    conn.executemany(
        "INSERT INTO listening_ports"
        " (observed_at, protocol, local_address, port, process_name, pid) VALUES (?,?,?,?,?,?)",
        [(ts, p.protocol, p.local_address, p.port, p.process_name, p.pid) for p in snap.ports],
    )
    return len(snap.ports)


def latest_port_snapshot(conn: sqlite3.Connection) -> tuple[datetime, list[ListeningPort]] | None:
    latest = conn.execute("SELECT MAX(observed_at) FROM listening_ports").fetchone()[0]
    if latest is None:
        return None
    rows = conn.execute(
        "SELECT protocol, local_address, port, process_name, pid FROM listening_ports"
        " WHERE observed_at = ? ORDER BY protocol, port, local_address",
        (latest,),
    ).fetchall()
    return from_db(latest), [
        ListeningPort(
            protocol=r["protocol"],
            local_address=r["local_address"],
            port=r["port"],
            process_name=r["process_name"],
            pid=r["pid"],
        )
        for r in rows
    ]
