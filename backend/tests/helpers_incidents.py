"""Builders shared by the incident tests: detection events shaped like the real rules' output."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

from sentinelpi.config import IncidentSettings, ScoringSettings
from sentinelpi.events import Event, EventSource, Severity
from sentinelpi.incidents.correlator import IncidentCorrelator
from sentinelpi.storage import events_repo

_TYPES = {
    "SP-001": ("detection.ssh_repeated_failures", EventSource.AUTH_LOG, Severity.HIGH),
    "SP-002": ("detection.new_listening_port", EventSource.PORT_INVENTORY, Severity.MEDIUM),
    "SP-003": ("detection.sustained_high_cpu", EventSource.SYSTEM_METRICS, Severity.LOW),
    "SP-004": ("detection.watchlisted_process", EventSource.PROCESS_INVENTORY, Severity.MEDIUM),
}


def detection(
    ts: datetime,
    rule_id: str = "SP-001",
    *,
    ip: str | None = None,
    host: str = "pi",
    evidence: list[UUID] | None = None,
    severity: Severity | None = None,
    metadata: dict | None = None,
) -> Event:
    event_type, source, default_severity = _TYPES[rule_id]
    meta = {"rule_id": rule_id, "rule_name": rule_id, "explanation": f"{rule_id} fired"}
    if evidence:
        meta["evidence_event_ids"] = [str(e) for e in evidence]
    meta.update(metadata or {})
    return Event(
        timestamp=ts,
        source=source,
        event_type=event_type,
        severity=severity or default_severity,
        summary=f"{rule_id} test detection",
        source_ip=ip,
        host=host,
        metadata=meta,
    )


def put(conn, *events: Event) -> None:
    events_repo.insert_events(conn, list(events))


def correlator(**overrides) -> IncidentCorrelator:
    return IncidentCorrelator(IncidentSettings.model_validate(overrides), ScoringSettings())


def new_id() -> UUID:
    return uuid4()
