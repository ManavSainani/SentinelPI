from __future__ import annotations

import math
import sqlite3
from datetime import datetime, timedelta
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict, Field

from sentinelpi.api.deps import check_range, get_conn, utc
from sentinelpi.detection.rules.new_port import is_exposed
from sentinelpi.storage import detection_repo, telemetry_repo
from sentinelpi.storage.telemetry_repo import MAX_METRIC_ROWS
from sentinelpi.timeutil import utc_now

router = APIRouter(tags=["telemetry"])
MAX_POINTS = 1000


class MetricPoint(BaseModel):
    timestamp: datetime
    cpu_percent: float
    memory_percent: float
    disk_percent: float
    temperature_c: float | None = None
    uptime_seconds: float
    net_rx_bytes: int | None = None
    net_tx_bytes: int | None = None


class MetricsSeries(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    from_: datetime = Field(alias="from")
    to: datetime
    interval_seconds: int | None  # None = raw samples, otherwise each point is a bucket average
    truncated: bool  # the window held more rows than the server will read; oldest were dropped
    points: list[MetricPoint]


def _bucketed(samples: list, start: datetime, interval: int) -> list[MetricPoint]:
    buckets: dict[int, list] = {}
    for s in samples:
        buckets.setdefault(int((s.timestamp - start).total_seconds() // interval), []).append(s)
    points: list[MetricPoint] = []
    for _, group in sorted(buckets.items()):
        last = group[-1]
        temps = [g.temperature_c for g in group if g.temperature_c is not None]
        points.append(
            MetricPoint(
                timestamp=last.timestamp,
                cpu_percent=round(sum(g.cpu_percent for g in group) / len(group), 2),
                memory_percent=round(sum(g.memory_percent for g in group) / len(group), 2),
                disk_percent=round(sum(g.disk_percent for g in group) / len(group), 2),
                temperature_c=round(sum(temps) / len(temps), 2) if temps else None,
                uptime_seconds=last.uptime_seconds,  # counters keep the latest value
                net_rx_bytes=last.net_rx_bytes,
                net_tx_bytes=last.net_tx_bytes,
            )
        )
    return points


@router.get("/system/metrics", response_model=MetricsSeries)
def system_metrics(
    conn: Annotated[sqlite3.Connection, Depends(get_conn)],
    from_: Annotated[datetime | None, Query(alias="from")] = None,
    to: datetime | None = None,
    interval_seconds: Annotated[int | None, Query(ge=1, le=86_400)] = None,
) -> MetricsSeries:
    now = utc_now()
    end = utc(to) or now
    start = utc(from_) or end - timedelta(hours=1)
    check_range(start, end)
    rows = telemetry_repo.list_metrics(conn, since=start, until=end, limit=MAX_METRIC_ROWS)
    truncated = len(rows) >= MAX_METRIC_ROWS
    interval = interval_seconds
    if interval is None and len(rows) > MAX_POINTS:
        interval = math.ceil((end - start).total_seconds() / MAX_POINTS)
    if interval is not None:
        # Never return more than MAX_POINTS, whatever interval was asked for.
        interval = max(interval, math.ceil((end - start).total_seconds() / MAX_POINTS))
        points = _bucketed(rows, start, interval)
    else:
        points = [MetricPoint(**r.model_dump()) for r in rows]
    return MetricsSeries(
        from_=start, to=end, interval_seconds=interval, truncated=truncated, points=points
    )


class ProcessOut(BaseModel):
    pid: int
    name: str
    username: str | None = None
    cpu_percent: float
    memory_percent: float


class ProcessList(BaseModel):
    observed_at: datetime | None
    items: list[ProcessOut]
    total: int
    limit: int
    next_cursor: None = None


@router.get("/processes", response_model=ProcessList)
def processes(
    conn: Annotated[sqlite3.Connection, Depends(get_conn)],
    sort: Literal["cpu", "memory", "name"] = "cpu",
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> ProcessList:
    snap = telemetry_repo.latest_process_snapshot(conn)
    if snap is None:
        return ProcessList(observed_at=None, items=[], total=0, limit=limit)
    observed_at, procs = snap
    key = {
        "cpu": lambda p: (-p.cpu_percent, p.pid),
        "memory": lambda p: (-p.memory_percent, p.pid),
        "name": lambda p: (p.name.lower(), p.pid),
    }[sort]
    # The raw command line is never returned (and is never collected in the first place).
    items = [
        ProcessOut(**p.model_dump(exclude={"command_redacted"})) for p in sorted(procs, key=key)
    ]
    return ProcessList(observed_at=observed_at, items=items[:limit], total=len(items), limit=limit)


class ListenerOut(BaseModel):
    protocol: Literal["tcp", "udp"]
    local_address: str
    port: int
    process_name: str | None = None
    pid: int | None = None
    reachable_beyond_loopback: bool
    # True/False once you have approved a port baseline (and it could observe this protocol);
    # None when there is no baseline to compare with.
    in_baseline: bool | None = None


class ListenerList(BaseModel):
    observed_at: datetime | None
    baseline_captured_at: datetime | None = None
    items: list[ListenerOut]
    total: int
    limit: int
    next_cursor: None = None


@router.get("/network/listeners", response_model=ListenerList)
def listeners(
    conn: Annotated[sqlite3.Connection, Depends(get_conn)],
    protocol: Literal["tcp", "udp"] | None = None,
    exposed_only: bool = False,
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
) -> ListenerList:
    snap = telemetry_repo.latest_port_snapshot(conn)
    if snap is None:
        return ListenerList(observed_at=None, items=[], total=0, limit=limit)
    observed_at, ports = snap
    meta = detection_repo.get_baseline_meta(conn)
    known = detection_repo.get_baseline_keys(conn) if meta else set()

    def in_baseline(p) -> bool | None:
        if meta is None or p.protocol not in meta.protocols:
            return None  # nothing to compare against, or the baseline could not see this protocol
        return (p.protocol, p.port) in known

    items = [
        ListenerOut(
            **p.model_dump(),
            reachable_beyond_loopback=is_exposed(p.local_address),
            in_baseline=in_baseline(p),
        )
        for p in ports
        if (protocol is None or p.protocol == protocol)
    ]
    if exposed_only:
        items = [i for i in items if i.reachable_beyond_loopback]
    return ListenerList(
        observed_at=observed_at,
        baseline_captured_at=meta.captured_at if meta else None,
        items=items[:limit],
        total=len(items),
        limit=limit,
    )
