"""Rule interface. A rule is a small, deterministic, read-only function of the database
and a clock: same data + same `now` => same result. Rules never write; the engine does."""

from __future__ import annotations

import sqlite3
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sentinelpi.events import Event, Severity


@dataclass(frozen=True)
class Detection:
    rule_id: str
    dedupe_key: str  # one persistent condition = one key = one alert per cooldown
    event: Event


@dataclass
class RuleResult:
    detections: list[Detection] = field(default_factory=list)
    skipped_reason: str | None = None  # data missing/stale/incomplete: the rule was not judged
    note: str | None = None


class Rule(ABC):
    rule_id: str
    name: str
    description: str
    severity: Severity

    @property
    @abstractmethod
    def enabled(self) -> bool: ...

    @property
    @abstractmethod
    def cooldown(self) -> timedelta: ...

    @abstractmethod
    def thresholds(self) -> dict[str, Any]:
        """Effective configuration, shown by `rules` and stored in detection_rules."""

    @abstractmethod
    def evaluate(self, conn: sqlite3.Connection, now: datetime) -> RuleResult: ...

    def catalog_entry(self) -> dict[str, object]:
        return {
            "id": self.rule_id,
            "name": self.name,
            "enabled": self.enabled,
            "severity": self.severity.value,
            "thresholds": self.thresholds(),
            "description": self.description,
        }
