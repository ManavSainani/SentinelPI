"""Listening TCP/UDP port snapshot.

Linux: psutil works without root for the current user's sockets; sockets owned by other
users still appear but without pid/process name.
macOS: psutil needs root to list sockets, so we fall back to `lsof` (TCP only, current
user's processes). The fallback is reported as DEGRADED so the UI can say so.
"""

from __future__ import annotations

import socket
import subprocess
from collections.abc import Callable
from datetime import datetime
from typing import Any, Literal

import psutil
from pydantic import BaseModel, Field

from sentinelpi.collectors.base import (
    CollectionResult,
    CollectorState,
    make_status,
    utcnow,
)

NAME = "ports"
_LSOF_CMD = ["lsof", "-nP", "-iTCP", "-sTCP:LISTEN", "-Fpcn"]
_LSOF_TIMEOUT_S = 5


class ListeningPort(BaseModel):
    protocol: Literal["tcp", "udp"]
    local_address: str
    port: int = Field(ge=1, le=65535)
    pid: int | None = None
    process_name: str | None = None


class PortSnapshot(BaseModel):
    timestamp: datetime
    total_count: int
    truncated: bool
    ports: list[ListeningPort]


def parse_lsof_fields(text: str) -> list[ListeningPort]:
    """Parse `lsof -F pcn` output (p=pid, c=command, n=name) into listening TCP ports."""
    ports: list[ListeningPort] = []
    pid: int | None = None
    command: str | None = None
    for line in text.splitlines():
        if not line:
            continue
        tag, value = line[0], line[1:]
        if tag == "p":
            try:
                pid = int(value)
            except ValueError:
                pid = None
            command = None
        elif tag == "c":
            command = "".join(ch for ch in value if ch.isprintable())[:64] or None
        elif tag == "n" and "->" not in value and ":" in value:
            address, _, port_text = value.rpartition(":")
            try:
                port = int(port_text)
            except ValueError:
                continue
            if not 1 <= port <= 65535:
                continue
            ports.append(
                ListeningPort(
                    protocol="tcp",
                    local_address=address.strip("[]"),
                    port=port,
                    pid=pid,
                    process_name=command,
                )
            )
    return ports


class PortCollector:
    def __init__(
        self,
        limit: int = 200,
        psutil_mod: Any = psutil,
        runner: Callable[..., Any] = subprocess.run,
    ) -> None:
        self._ps = psutil_mod
        self._limit = limit
        self._run = runner

    def _process_name(self, pid: int, cache: dict[int, str | None]) -> str | None:
        if pid not in cache:
            try:
                cache[pid] = "".join(ch for ch in self._ps.Process(pid).name() if ch.isprintable())[
                    :64
                ]
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                cache[pid] = None
        return cache[pid]

    def _from_psutil(self) -> list[ListeningPort]:
        conns = self._ps.net_connections(kind="inet")
        names: dict[int, str | None] = {}
        seen: set[tuple[str, str, int, int | None]] = set()
        result: list[ListeningPort] = []
        for c in conns:
            if not c.laddr:
                continue
            if c.type == socket.SOCK_STREAM and c.status == psutil.CONN_LISTEN:
                proto: Literal["tcp", "udp"] = "tcp"
            elif c.type == socket.SOCK_DGRAM and not c.raddr:
                proto = "udp"  # UDP has no LISTEN state; unconnected + bound = receiving
            else:
                continue
            key = (proto, c.laddr.ip, c.laddr.port, c.pid)
            if key in seen or not 1 <= c.laddr.port <= 65535:
                continue
            seen.add(key)
            result.append(
                ListeningPort(
                    protocol=proto,
                    local_address=c.laddr.ip,
                    port=c.laddr.port,
                    pid=c.pid,
                    process_name=self._process_name(c.pid, names) if c.pid else None,
                )
            )
        return result

    def _finish(
        self,
        ports: list[ListeningPort],
        state: CollectorState,
        detail: str | None,
        missing: list[str] | None = None,
    ) -> CollectionResult[PortSnapshot]:
        ports.sort(key=lambda p: (p.protocol, p.port, p.local_address, p.pid or 0))
        snapshot = PortSnapshot(
            timestamp=utcnow(),
            total_count=len(ports),
            truncated=len(ports) > self._limit,
            ports=ports[: self._limit],
        )
        return CollectionResult[PortSnapshot](
            status=make_status(NAME, state, detail=detail, missing=missing), data=snapshot
        )

    def _lsof_fallback(self) -> CollectionResult[PortSnapshot]:
        why = "socket listing needs elevated privileges on this OS"
        try:
            proc = self._run(
                _LSOF_CMD, capture_output=True, text=True, timeout=_LSOF_TIMEOUT_S, check=False
            )
        except FileNotFoundError:
            status = make_status(NAME, CollectorState.UNAVAILABLE, detail=f"{why}; lsof not found")
            return CollectionResult[PortSnapshot](status=status)
        except (subprocess.TimeoutExpired, OSError) as exc:
            status = make_status(
                NAME, CollectorState.UNAVAILABLE, detail=f"{why}; lsof failed: {type(exc).__name__}"
            )
            return CollectionResult[PortSnapshot](status=status)
        ports = parse_lsof_fields(proc.stdout or "")
        return self._finish(
            ports,
            CollectorState.DEGRADED,
            f"{why}; used lsof fallback (TCP only, current user's processes)",
            missing=["udp", "other_users_processes"],
        )

    def collect(self) -> CollectionResult[PortSnapshot]:
        try:
            ports = self._from_psutil()
        except (psutil.AccessDenied, PermissionError):
            return self._lsof_fallback()
        except Exception as exc:  # noqa: BLE001
            status = make_status(NAME, CollectorState.ERROR, detail=type(exc).__name__)
            return CollectionResult[PortSnapshot](status=status)

        unattributed = sum(1 for p in ports if p.pid is None)
        detail = (
            f"process attribution unavailable for {unattributed} socket(s) (owned by other users)"
            if unattributed
            else None
        )
        return self._finish(ports, CollectorState.OK, detail)
