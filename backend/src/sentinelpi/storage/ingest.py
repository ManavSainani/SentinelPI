"""Glue between collectors and storage: persist telemetry snapshots."""

from __future__ import annotations

import sqlite3

from pydantic import BaseModel

from sentinelpi.collectors import HostTelemetry
from sentinelpi.collectors.base import CollectionResult
from sentinelpi.collectors.metrics import MetricsSample
from sentinelpi.collectors.ports import PortSnapshot
from sentinelpi.collectors.processes import ProcessSnapshot
from sentinelpi.storage import state_repo, telemetry_repo
from sentinelpi.storage.detection_repo import COVERAGE_KEY


class IngestReport(BaseModel):
    metrics_stored: bool = False
    process_rows: int = 0
    port_rows: int = 0
    skipped: list[str] = []  # collectors that produced no data (see their status)


def store_metrics(conn: sqlite3.Connection, result: CollectionResult[MetricsSample]) -> bool:
    if result.data is None:
        return False
    telemetry_repo.insert_metrics(conn, result.data)
    return True


def store_snapshots(
    conn: sqlite3.Connection,
    processes: CollectionResult[ProcessSnapshot],
    ports: CollectionResult[PortSnapshot],
) -> IngestReport:
    report = IngestReport(skipped=[])
    if processes.data is not None:
        report.process_rows = telemetry_repo.insert_process_snapshot(conn, processes.data)
    else:
        report.skipped.append("processes")
    if ports.data is not None:
        report.port_rows = telemetry_repo.insert_port_snapshot(conn, ports.data)
        # Remember which protocols this snapshot could actually see (macOS fallback is
        # TCP-only), so a baseline never treats "not visible" as "not listening".
        coverage = "tcp" if "udp" in ports.status.missing else "tcp,udp"
        state_repo.set_state(conn, COVERAGE_KEY, coverage)
    else:
        report.skipped.append("ports")
    return report


def store_telemetry(conn: sqlite3.Connection, telemetry: HostTelemetry) -> IngestReport:
    report = store_snapshots(conn, telemetry.processes, telemetry.ports)
    report.metrics_stored = store_metrics(conn, telemetry.metrics)
    if not report.metrics_stored:
        report.skipped.insert(0, "metrics")
    return report
