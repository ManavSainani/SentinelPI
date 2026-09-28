"""Bounded process snapshot.

Privacy: command-line arguments, environment, and working directory are NEVER read.
`command_redacted` is just the sanitized process name. Argument capture (with redaction)
would be an explicit opt-in feature later, not a default.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

import psutil
from pydantic import BaseModel, Field

from sentinelpi.collectors.base import (
    CollectionResult,
    CollectorState,
    make_status,
    utcnow,
)

NAME = "processes"
# Deliberately excludes cmdline, environ, exe, cwd, open_files, connections.
_ATTRS = ["pid", "name", "username", "cpu_percent", "memory_percent"]
_MAX_NAME = 64


class ProcessInfo(BaseModel):
    pid: int
    name: str
    username: str | None = None
    cpu_percent: float = Field(ge=0)  # can exceed 100 on multi-core hosts
    memory_percent: float = Field(ge=0, le=100)
    command_redacted: str


class ProcessSnapshot(BaseModel):
    timestamp: datetime
    total_count: int
    truncated: bool
    processes: list[ProcessInfo]


def _clean_name(name: str | None) -> str:
    if not name:
        return "<unknown>"
    cleaned = "".join(ch for ch in name if ch.isprintable())[:_MAX_NAME].strip()
    return cleaned or "<unknown>"


class ProcessCollector:
    def __init__(self, limit: int = 50, psutil_mod: Any = psutil) -> None:
        self._ps = psutil_mod
        self._limit = limit
        try:  # Prime per-process CPU counters so the first real sample is meaningful.
            for _ in self._ps.process_iter(["cpu_percent"]):
                pass
        except Exception:  # noqa: BLE001
            pass

    def collect(self) -> CollectionResult[ProcessSnapshot]:
        try:
            infos = [p.info for p in self._ps.process_iter(_ATTRS)]
        except Exception as exc:  # noqa: BLE001
            status = make_status(NAME, CollectorState.ERROR, detail=type(exc).__name__)
            return CollectionResult[ProcessSnapshot](status=status)

        restricted = 0
        items: list[ProcessInfo] = []
        for info in infos:
            if info.get("pid") is None:
                continue
            if any(info.get(k) is None for k in ("name", "cpu_percent", "memory_percent")):
                restricted += 1
            name = _clean_name(info.get("name"))
            items.append(
                ProcessInfo(
                    pid=int(info["pid"]),
                    name=name,
                    username=info.get("username"),
                    cpu_percent=max(0.0, float(info.get("cpu_percent") or 0.0)),
                    memory_percent=max(0.0, min(100.0, float(info.get("memory_percent") or 0.0))),
                    command_redacted=name,
                )
            )

        items.sort(key=lambda p: (-(p.cpu_percent + p.memory_percent), p.pid))
        snapshot = ProcessSnapshot(
            timestamp=utcnow(),
            total_count=len(items),
            truncated=len(items) > self._limit,
            processes=items[: self._limit],
        )
        detail = f"{restricted} process(es) had restricted fields" if restricted else None
        return CollectionResult[ProcessSnapshot](
            status=make_status(NAME, CollectorState.OK, detail=detail), data=snapshot
        )
