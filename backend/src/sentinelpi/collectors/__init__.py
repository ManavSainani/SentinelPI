"""Host telemetry collectors. Read-only: collectors observe, they never act."""

from __future__ import annotations

from pydantic import BaseModel

from sentinelpi.collectors.base import CollectionResult, CollectorState, CollectorStatus
from sentinelpi.collectors.metrics import MetricsCollector, MetricsSample
from sentinelpi.collectors.ports import PortCollector, PortSnapshot
from sentinelpi.collectors.processes import ProcessCollector, ProcessSnapshot
from sentinelpi.config import CollectionSettings


class HostTelemetry(BaseModel):
    metrics: CollectionResult[MetricsSample]
    processes: CollectionResult[ProcessSnapshot]
    ports: CollectionResult[PortSnapshot]


class HostCollectors:
    def __init__(self, settings: CollectionSettings | None = None) -> None:
        s = settings or CollectionSettings()
        self.metrics = MetricsCollector(disk_path=s.disk_path)
        self.processes = ProcessCollector(limit=s.process_limit)
        self.ports = PortCollector(limit=s.port_limit)

    def collect_all(self) -> HostTelemetry:
        return HostTelemetry(
            metrics=self.metrics.collect(),
            processes=self.processes.collect(),
            ports=self.ports.collect(),
        )


__all__ = [
    "CollectionResult",
    "CollectorState",
    "CollectorStatus",
    "HostCollectors",
    "HostTelemetry",
    "MetricsCollector",
    "PortCollector",
    "ProcessCollector",
]
