"""Shared types for host collectors.

Every collector returns a CollectionResult: the data (or None) plus a status that says
*why* data is missing. A missing optional sensor is normal, not an error.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Generic, TypeVar

from pydantic import BaseModel, Field

T = TypeVar("T")


class CollectorState(StrEnum):
    OK = "ok"  # collected what this collector is designed to collect
    DEGRADED = "degraded"  # partial data or a fallback path was used
    UNAVAILABLE = "unavailable"  # this host/OS/permission level cannot provide it
    ERROR = "error"  # unexpected failure


class CollectorStatus(BaseModel):
    name: str
    state: CollectorState
    detail: str | None = None
    # Optional fields that could not be provided (e.g. ["temperature_c"]).
    missing: list[str] = Field(default_factory=list)
    collected_at: datetime


class CollectionResult(BaseModel, Generic[T]):  # noqa: UP046 (keep 3.11-compatible syntax)
    status: CollectorStatus
    data: T | None = None


def utcnow() -> datetime:
    return datetime.now(UTC)


def make_status(
    name: str,
    state: CollectorState,
    detail: str | None = None,
    missing: list[str] | None = None,
) -> CollectorStatus:
    return CollectorStatus(
        name=name, state=state, detail=detail, missing=missing or [], collected_at=utcnow()
    )
