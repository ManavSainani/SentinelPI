"""Incident data shapes shared by storage, the correlator, the CLI and (later) the API."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field

from sentinelpi.events import Severity


class IncidentStatus(StrEnum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"

    @property
    def is_active(self) -> bool:
        """Active incidents can still receive evidence and are never deleted by retention."""
        return self in (IncidentStatus.OPEN, IncidentStatus.ACKNOWLEDGED)


class Incident(BaseModel):
    id: str
    title: str
    description: str
    severity: Severity
    risk_score: int = Field(ge=0, le=100)
    status: IncidentStatus
    host: str
    source_ip: str | None = None  # None = host-local activity (ports, processes, CPU)
    rule_ids: list[str] = Field(default_factory=list)
    risk_breakdown: list[dict[str, Any]] = Field(default_factory=list)
    first_seen: datetime
    last_seen: datetime
    created_at: datetime
    updated_at: datetime
    resolution_note: str | None = None
    evidence_count: int = 0

    def to_api(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


class TimelineItem(BaseModel):
    """One row of an incident's history: a piece of evidence or an audit entry."""

    at: datetime
    kind: Literal["event", "audit"]
    # evidence rows
    event_id: str | None = None
    event_type: str | None = None
    severity: Severity | None = None
    summary: str | None = None
    # audit rows
    audit_kind: str | None = None
    actor: str | None = None
    from_status: str | None = None
    to_status: str | None = None
    note: str | None = None
