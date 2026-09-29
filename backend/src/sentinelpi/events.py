"""Normalized event contract (spec section 6). Validation and redaction happen here, so
anything that reaches storage or an API response has already been sanitized."""

from __future__ import annotations

import ipaddress
import re
import socket
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Any
from uuid import UUID, uuid4

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, field_validator

from sentinelpi.safety import clean_text, sanitize_metadata
from sentinelpi.timeutil import to_utc


class EventSource(StrEnum):
    AUTH_LOG = "auth_log"
    SYSTEM_METRICS = "system_metrics"
    PROCESS_INVENTORY = "process_inventory"
    PORT_INVENTORY = "port_inventory"
    TEST = "test"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _ORDER.index(self)


_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


def severities_at_least(minimum: Severity) -> list[Severity]:
    return [s for s in _ORDER if s.rank >= minimum.rank]


_EVENT_TYPE = re.compile(r"^[a-z][a-z0-9_.]{0,63}$")
UtcDatetime = Annotated[datetime, AfterValidator(to_utc)]


class Event(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: UUID = Field(default_factory=uuid4)
    timestamp: UtcDatetime
    source: EventSource
    event_type: str
    severity: Severity
    summary: str
    source_ip: str | None = None
    username: str | None = None
    process_name: str | None = None
    host: str = Field(default_factory=socket.gethostname)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("event_type")
    @classmethod
    def _event_type(cls, v: str) -> str:
        if not _EVENT_TYPE.match(v):
            raise ValueError("event_type must be lowercase letters, digits, '_' or '.'")
        return v

    @field_validator("summary")
    @classmethod
    def _summary(cls, v: str) -> str:
        cleaned = clean_text(v, 300)
        if not cleaned:
            raise ValueError("summary must not be empty")
        return cleaned

    @field_validator("source_ip")
    @classmethod
    def _source_ip(cls, v: str | None) -> str | None:
        return None if v is None else str(ipaddress.ip_address(v.strip()))

    @field_validator("username", "process_name")
    @classmethod
    def _short_text(cls, v: str | None) -> str | None:
        if v is None:
            return None
        return clean_text(v, 64) or None

    @field_validator("host")
    @classmethod
    def _host(cls, v: str) -> str:
        cleaned = clean_text(v, 255)
        if not cleaned:
            raise ValueError("host must not be empty")
        return cleaned

    @field_validator("metadata")
    @classmethod
    def _metadata(cls, v: dict[str, Any]) -> dict[str, Any]:
        return sanitize_metadata(v)

    def to_api(self) -> dict[str, Any]:
        """JSON-safe dict for API responses (UTC ISO-8601 timestamps, string UUID)."""
        return self.model_dump(mode="json")
