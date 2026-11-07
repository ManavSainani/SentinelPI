from __future__ import annotations

import socket
import sqlite3
from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from sentinelpi import __version__
from sentinelpi.api.deps import get_conn, get_settings
from sentinelpi.config import Settings
from sentinelpi.events import Severity
from sentinelpi.incidents.models import Incident, IncidentStatus
from sentinelpi.monitor import HEARTBEAT_KEY
from sentinelpi.storage import incidents_repo, state_repo, telemetry_repo
from sentinelpi.timeutil import from_db, utc_now

router = APIRouter(tags=["system"])


class MonitorStatus(BaseModel):
    running: bool
    last_heartbeat: datetime | None
    age_seconds: float | None


class MetricsStatus(BaseModel):
    observed_at: datetime
    age_seconds: float
    stale: bool
    cpu_percent: float
    memory_percent: float
    disk_percent: float
    temperature_c: float | None
    uptime_seconds: float


class AlertSummary(BaseModel):
    id: str
    title: str
    severity: Severity
    risk_score: int
    status: IncidentStatus
    source_ip: str | None
    first_seen: datetime
    last_seen: datetime

    @classmethod
    def of(cls, i: Incident) -> AlertSummary:
        return cls(**i.model_dump(include=set(cls.model_fields)))


class SystemStatus(BaseModel):
    generated_at: datetime
    host: str
    overall: Literal["ok", "warning", "alert"]
    reasons: list[str]
    monitor: MonitorStatus
    metrics: MetricsStatus | None
    incidents: dict[str, int]
    active_alert: AlertSummary | None
    open_incidents: list[AlertSummary]


def _monitor_status(conn: sqlite3.Connection, settings: Settings, now: datetime) -> MonitorStatus:
    raw = state_repo.get_state(conn, HEARTBEAT_KEY)
    if raw is None:
        return MonitorStatus(running=False, last_heartbeat=None, age_seconds=None)
    beat = from_db(raw)
    age = max(0.0, (now - beat).total_seconds())
    # Alive if it has reported within three detection cycles (plus slack for a slow cycle).
    return MonitorStatus(
        running=age <= 3 * settings.monitor.detection_interval_seconds + 15,
        last_heartbeat=beat,
        age_seconds=round(age, 1),
    )


@router.get("/system/status", response_model=SystemStatus)
def system_status(
    conn: Annotated[sqlite3.Connection, Depends(get_conn)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> SystemStatus:
    """One small summary for the kiosk and any status light: what is wrong, if anything."""
    now = utc_now()
    monitor = _monitor_status(conn, settings, now)

    metrics: MetricsStatus | None = None
    sample = telemetry_repo.latest_metrics(conn)
    if sample is not None:
        age = max(0.0, (now - sample.timestamp).total_seconds())
        metrics = MetricsStatus(
            observed_at=sample.timestamp,
            age_seconds=round(age, 1),
            stale=age > max(30, 3 * settings.monitor.metrics_interval_seconds),
            **sample.model_dump(
                include={
                    "cpu_percent",
                    "memory_percent",
                    "disk_percent",
                    "temperature_c",
                    "uptime_seconds",
                }
            ),
        )

    open_incidents = incidents_repo.list_incidents(conn, status=IncidentStatus.OPEN, limit=50)
    # Most severe first, then most recently active. Acknowledged incidents stop alerting.
    open_incidents.sort(key=lambda i: (-i.severity.rank, -i.last_seen.timestamp()))

    reasons: list[str] = []
    overall: Literal["ok", "warning", "alert"] = "ok"
    if open_incidents:
        top = open_incidents[0]
        overall = "alert" if top.severity.rank >= Severity.HIGH.rank else "warning"
        reasons.append(f"{len(open_incidents)} open incident(s); highest is {top.severity.value}")
    if not monitor.running:
        overall = "warning" if overall == "ok" else overall
        reasons.append("the monitor is not running (data may be out of date)")
    if metrics is not None and metrics.stale:
        overall = "warning" if overall == "ok" else overall
        reasons.append("system metrics are out of date")

    return SystemStatus(
        generated_at=now,
        host=socket.gethostname(),
        overall=overall,
        reasons=reasons,
        monitor=monitor,
        metrics=metrics,
        incidents=incidents_repo.count_by_status(conn),
        active_alert=AlertSummary.of(open_incidents[0]) if open_incidents else None,
        open_incidents=[AlertSummary.of(i) for i in open_incidents[:5]],
    )


class AboutInfo(BaseModel):
    version: str
    host: str
    retention_days: dict[str, int]
    intervals_seconds: dict[str, int]
    collects: list[str]
    never_collects: list[str]


@router.get("/system/about", response_model=AboutInfo)
def about(settings: Annotated[Settings, Depends(get_settings)]) -> AboutInfo:
    """What this installation collects and keeps, stated from its own configuration."""
    r, m = settings.retention, settings.monitor
    return AboutInfo(
        version=__version__,
        host=socket.gethostname(),
        retention_days={
            "events": r.events_days,
            "metrics": r.metrics_days,
            "snapshots": r.snapshot_days,
            "resolved_incidents": r.incident_days,
        },
        intervals_seconds={
            "metrics": m.metrics_interval_seconds,
            "processes_and_ports": m.snapshot_interval_seconds,
            "ssh_logs": m.auth_interval_seconds,
            "detection": m.detection_interval_seconds,
        },
        collects=[
            "CPU, memory, disk, temperature and uptime",
            "Process names, owners and resource use",
            "Listening ports and the process that owns them",
            "SSH sign-in events from the system log",
        ],
        never_collects=[
            "Command lines and environment variables",
            "File contents",
            "Passwords or the user names typed in failed logins for accounts that do not exist",
        ],
    )
