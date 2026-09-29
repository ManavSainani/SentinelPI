"""Glue between collectors and storage: persist one telemetry snapshot."""

from __future__ import annotations

import sqlite3

from pydantic import BaseModel

from sentinelpi.collectors import HostTelemetry
from sentinelpi.storage import telemetry_repo


class IngestReport(BaseModel):
    metrics_stored: bool = False
    process_rows: int = 0
    port_rows: int = 0
    skipped: list[str] = []  # collectors that produced no data (see their status)


def store_telemetry(conn: sqlite3.Connection, telemetry: HostTelemetry) -> IngestReport:
    report = IngestReport(skipped=[])
    if telemetry.metrics.data is not None:
        telemetry_repo.insert_metrics(conn, telemetry.metrics.data)
        report.metrics_stored = True
    else:
        report.skipped.append("metrics")
    if telemetry.processes.data is not None:
        report.process_rows = telemetry_repo.insert_process_snapshot(conn, telemetry.processes.data)
    else:
        report.skipped.append("processes")
    if telemetry.ports.data is not None:
        report.port_rows = telemetry_repo.insert_port_snapshot(conn, telemetry.ports.data)
    else:
        report.skipped.append("ports")
    return report
