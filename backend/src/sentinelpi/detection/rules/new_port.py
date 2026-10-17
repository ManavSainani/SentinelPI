"""SP-002: a listening port/protocol appears that is absent from the approved baseline.

The baseline is captured explicitly (`python -m sentinelpi.detection baseline capture`) after
you review the list, so a bad first boot can never silently become "normal". Until a baseline
exists the rule is skipped, not guessed. Only protocols the baseline could actually observe are
compared, so a TCP-only baseline (macOS fallback) never reports every UDP port as new.
"""

from __future__ import annotations

import ipaddress
import sqlite3
from datetime import datetime, timedelta
from typing import Any

from sentinelpi.collectors.ports import ListeningPort
from sentinelpi.config import NewPortRule as Config
from sentinelpi.config import ScoringSettings
from sentinelpi.detection.base import Detection, Rule, RuleResult
from sentinelpi.detection.scoring import rule_weight
from sentinelpi.events import Event, EventSource, Severity
from sentinelpi.storage import detection_repo, telemetry_repo
from sentinelpi.timeutil import to_db


def is_exposed(address: str) -> bool:
    """True unless the listener is bound to loopback only."""
    if address in {"localhost"}:
        return False
    try:
        return not ipaddress.ip_address(address).is_loopback
    except ValueError:
        return True  # "*", "::", empty or unparseable: assume reachable from the network


class NewPortRule(Rule):
    rule_id = "SP-002"
    name = "New listening port"
    description = (
        "A listening port/protocol that is not in the approved baseline appears in a later "
        "snapshot."
    )
    severity = Severity.MEDIUM

    def __init__(self, cfg: Config, scoring: ScoringSettings, max_age: timedelta) -> None:
        self.cfg = cfg
        self._points = rule_weight(self.rule_id, scoring)
        self._max_age = max_age

    @property
    def enabled(self) -> bool:
        return self.cfg.enabled

    @property
    def cooldown(self) -> timedelta:
        return timedelta(minutes=self.cfg.cooldown_minutes)

    def thresholds(self) -> dict[str, Any]:
        return {
            "protocols": list(self.cfg.protocols),
            "ignored_ports": self.cfg.ignored_ports,
            "cooldown_minutes": self.cfg.cooldown_minutes,
            "max_per_run": self.cfg.max_per_run,
        }

    def evaluate(self, conn: sqlite3.Connection, now: datetime) -> RuleResult:
        meta = detection_repo.get_baseline_meta(conn)
        if meta is None:
            return RuleResult(
                skipped_reason="no baseline captured yet "
                "(run: python -m sentinelpi.detection baseline capture)"
            )
        snap = telemetry_repo.latest_port_snapshot(conn)
        if snap is None:
            return RuleResult(skipped_reason="no port snapshot yet")
        observed_at, ports = snap
        if now - observed_at > self._max_age:
            return RuleResult(skipped_reason="latest port snapshot is stale")

        covered = set(meta.protocols) & set(self.cfg.protocols)
        baseline = detection_repo.get_baseline_keys(conn)
        new: dict[tuple[str, int], list[ListeningPort]] = {}
        for p in ports:
            key = (p.protocol, p.port)
            if (
                p.protocol in covered
                and key not in baseline
                and f"{p.protocol}/{p.port}" not in self.cfg.ignored_ports
            ):
                new.setdefault(key, []).append(p)

        keys = sorted(new)
        result = RuleResult()
        if len(keys) > self.cfg.max_per_run:
            result.note = f"{len(keys)} new ports; reporting the first {self.cfg.max_per_run}"
        for key in keys[: self.cfg.max_per_run]:
            result.detections.append(
                self._detection(key, new[key], meta.captured_at, observed_at, now)
            )
        return result

    def _detection(
        self,
        key: tuple[str, int],
        items: list[ListeningPort],
        baseline_at: datetime,
        observed_at: datetime,
        now: datetime,
    ) -> Detection:
        proto, port = key
        addresses = sorted({i.local_address for i in items})
        process = next((i.process_name for i in items if i.process_name), None)
        pid = next((i.pid for i in items if i.pid is not None), None)
        exposed = any(is_exposed(a) for a in addresses)
        summary = f"SP-002: new {proto} listening port {port}"
        if process:
            summary += f" ({process})"
        summary += " reachable beyond loopback" if exposed else " (loopback only)"
        metadata: dict[str, Any] = {
            "rule_id": self.rule_id,
            "rule_name": self.name,
            "trigger": "listening port/protocol absent from the approved baseline",
            "explanation": f"{proto}/{port} is listening but was not in the baseline captured at "
            f"{to_db(baseline_at)}.",
            "protocol": proto,
            "port": port,
            "local_addresses": addresses[:10],
            "exposed": exposed,
            "pid": pid,
            "observed_at": to_db(observed_at),
            "baseline_captured_at": to_db(baseline_at),
            "dedupe_key": f"{self.rule_id}:{proto}/{port}",
            "risk_points": self._points,
        }
        event = Event(
            timestamp=now,
            source=EventSource.PORT_INVENTORY,
            event_type="detection.new_listening_port",
            severity=self.severity,
            summary=summary,
            process_name=process,
            metadata=metadata,
        )
        return Detection(self.rule_id, f"{self.rule_id}:{proto}/{port}", event)
