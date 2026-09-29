"""Deterministic synthetic data for tests and demos.

Same seed + same start time => identical output, including event UUIDs. Every event uses
source "test" so it can never be mistaken for real evidence. IPs come from the RFC 5737
documentation ranges, which are guaranteed not to be routable.
"""

from __future__ import annotations

import math
import random
from datetime import datetime, timedelta
from uuid import UUID

from sentinelpi.collectors.metrics import MetricsSample
from sentinelpi.events import Event, EventSource, Severity

_DOC_NETS = ("203.0.113", "198.51.100", "192.0.2")
_USERS = ("root", "admin", "pi", "ubuntu", "test", "oracle", "postgres", "git")
_PROCS = ("nc", "xmrig", "python3", "sshd", "cron")


def generate_events(
    count: int,
    *,
    start: datetime,
    seed: int = 1337,
    host: str = "test-host",
    step_seconds: int = 30,
) -> list[Event]:
    rng = random.Random(seed)
    events: list[Event] = []
    for i in range(count):
        ip = f"{rng.choice(_DOC_NETS)}.{rng.randint(1, 254)}"
        user = rng.choice(_USERS)
        kind = rng.choice(["ssh_fail", "ssh_fail", "ssh_ok", "port", "proc", "cpu"])
        common = {
            "id": UUID(int=rng.getrandbits(128), version=4),
            "timestamp": start + timedelta(seconds=i * step_seconds),
            "source": EventSource.TEST,
            "host": host,
        }
        if kind == "ssh_fail":
            events.append(
                Event(
                    **common,
                    event_type="auth.ssh_failed_login",
                    severity=Severity.LOW,
                    summary=f"Failed SSH login for {user} from {ip}",
                    source_ip=ip,
                    username=user,
                    metadata={"method": "password", "port": 22},
                )
            )
        elif kind == "ssh_ok":
            events.append(
                Event(
                    **common,
                    event_type="auth.ssh_successful_login",
                    severity=Severity.INFO,
                    summary=f"Successful SSH login for {user} from {ip}",
                    source_ip=ip,
                    username=user,
                    metadata={"method": "publickey"},
                )
            )
        elif kind == "port":
            port = rng.choice([2222, 4444, 8080, 31337])
            events.append(
                Event(
                    **common,
                    event_type="network.new_listening_port",
                    severity=Severity.MEDIUM,
                    summary=f"New listening port tcp/{port}",
                    metadata={"protocol": "tcp", "port": port},
                )
            )
        elif kind == "proc":
            proc = rng.choice(_PROCS)
            events.append(
                Event(
                    **common,
                    event_type="process.watchlist_match",
                    severity=Severity.MEDIUM,
                    summary=f"Watchlisted process observed: {proc}",
                    process_name=proc,
                    metadata={"watchlist": "default"},
                )
            )
        else:
            events.append(
                Event(
                    **common,
                    event_type="system.high_cpu",
                    severity=Severity.LOW,
                    summary="CPU usage stayed high",
                    metadata={"cpu_percent": round(rng.uniform(85, 99), 1)},
                )
            )
    return events


def generate_metrics(
    count: int, *, start: datetime, seed: int = 1337, interval_seconds: int = 10
) -> list[MetricsSample]:
    rng = random.Random(seed)
    rx = tx = 0
    samples: list[MetricsSample] = []
    for i in range(count):
        rx += rng.randint(1_000, 50_000)
        tx += rng.randint(500, 20_000)
        samples.append(
            MetricsSample(
                timestamp=start + timedelta(seconds=i * interval_seconds),
                cpu_percent=round(min(100.0, 20 + 15 * math.sin(i / 20) + rng.uniform(0, 10)), 1),
                memory_percent=round(40 + rng.uniform(0, 5), 1),
                disk_percent=round(31 + i * 0.0005, 2),
                temperature_c=round(45 + 8 * math.sin(i / 30) + rng.uniform(0, 2), 1),
                uptime_seconds=float(100_000 + i * interval_seconds),
                net_rx_bytes=rx,
                net_tx_bytes=tx,
            )
        )
    return samples
