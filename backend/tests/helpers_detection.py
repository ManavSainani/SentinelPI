"""Builders shared by the detection tests."""

from __future__ import annotations

from datetime import datetime, timedelta
from uuid import UUID, uuid4

from sentinelpi.collectors.metrics import MetricsSample
from sentinelpi.collectors.ports import ListeningPort, PortSnapshot
from sentinelpi.collectors.processes import ProcessInfo, ProcessSnapshot
from sentinelpi.config import DetectionSettings
from sentinelpi.detection.engine import DetectionEngine
from sentinelpi.events import Event, EventSource, Severity
from sentinelpi.storage import detection_repo, events_repo, telemetry_repo

FAILED = "auth.ssh_failed_login"
INVALID = "auth.ssh_invalid_user"
SUCCESS = "auth.ssh_successful_login"


def auth_event(
    ts: datetime,
    kind: str = FAILED,
    *,
    ip: str = "203.0.113.9",
    port: int | None = None,
    user: str | None = None,
    user_exists: bool | None = False,
    source: EventSource = EventSource.AUTH_LOG,
    eid: UUID | None = None,
    host: str = "pi",
) -> Event:
    meta: dict = {"log_source": "journal"}
    if user_exists is not None:
        meta["user_exists"] = user_exists
    if port is not None:
        meta["src_port"] = port
    return Event(
        id=eid or uuid4(),
        timestamp=ts,
        source=source,
        event_type=kind,
        severity=Severity.INFO if kind == SUCCESS else Severity.LOW,
        summary=f"{kind} from {ip}",
        source_ip=ip,
        username=user,
        host=host,
        metadata=meta,
    )


def burst(start: datetime, count: int, step_seconds: float = 10, **kw) -> list[Event]:
    """`count` failed logins, one every `step_seconds`, each on its own connection."""
    return [
        auth_event(start + timedelta(seconds=i * step_seconds), port=40000 + i, **kw)
        for i in range(count)
    ]


def metric(ts: datetime, cpu: float) -> MetricsSample:
    return MetricsSample(
        timestamp=ts,
        cpu_percent=cpu,
        memory_percent=30.0,
        disk_percent=40.0,
        temperature_c=50.0,
        uptime_seconds=1000.0,
    )


def cpu_series(now: datetime, cpu: float, *, seconds: int = 300, step: int = 10, skip=()):
    """Samples from now-seconds .. now inclusive; `skip` removes samples by index."""
    n = seconds // step
    return [
        metric(now - timedelta(seconds=seconds - i * step), cpu)
        for i in range(n + 1)
        if i not in skip
    ]


def put_ports(conn, ts: datetime, ports: list[tuple]) -> None:
    """ports: (protocol, port, address, process_name)."""
    items = [
        ListeningPort(protocol=p, port=n, local_address=a, process_name=name)
        for p, n, a, name in ports
    ]
    telemetry_repo.insert_port_snapshot(
        conn, PortSnapshot(timestamp=ts, total_count=len(items), truncated=False, ports=items)
    )


def put_baseline(conn, ts: datetime, ports: list[tuple], protocols=("tcp", "udp")) -> None:
    items = [
        ListeningPort(protocol=p, port=n, local_address=a, process_name=name)
        for p, n, a, name in ports
    ]
    detection_repo.replace_baseline(conn, items, list(protocols), ts)


def put_processes(conn, ts: datetime, procs: list[tuple]) -> None:
    """procs: (pid, name, username, cpu, mem)."""
    items = [
        ProcessInfo(
            pid=pid,
            name=name,
            username=user,
            cpu_percent=cpu,
            memory_percent=mem,
            command_redacted=name,
        )
        for pid, name, user, cpu, mem in procs
    ]
    telemetry_repo.insert_process_snapshot(
        conn,
        ProcessSnapshot(timestamp=ts, total_count=len(items), truncated=False, processes=items),
    )


def engine(**overrides) -> DetectionEngine:
    return DetectionEngine(DetectionSettings.model_validate(overrides))


def detection_events(conn, event_type: str | None = None) -> list[Event]:
    events = events_repo.list_events(conn, limit=500, event_type=event_type)
    return [e for e in events if e.event_type.startswith("detection.")]
