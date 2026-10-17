"""SP-001: at least N failed SSH authentication attempts from one source IP within a window.

Counting (from real Pi logs): one SSH connection logs an "invalid user" event and then one
"failed login" event per password typed, all sharing the connection's source port. So each
failed-login event is one attempt, and an invalid-user event counts only when its connection
produced no failed-login event (password login disabled), so one attempt is never counted
twice. The window is inclusive: N attempts spanning exactly `window` minutes still trigger.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from sentinelpi.config import ScoringSettings
from sentinelpi.config import SshFailuresRule as Config
from sentinelpi.detection.base import Detection, Rule, RuleResult
from sentinelpi.detection.scoring import rule_weight
from sentinelpi.events import Event, EventSource, Severity
from sentinelpi.timeutil import from_db, to_db

FAILED = "auth.ssh_failed_login"
INVALID = "auth.ssh_invalid_user"
SUCCESS = "auth.ssh_successful_login"
MAX_ROWS = 10_000  # bound the work per run; truncation is reported, never silent
MAX_EVIDENCE = 40
_SAME_ATTEMPT_SECONDS = 2  # legacy invalid-user lines carry no port


@dataclass
class _Attempt:
    ts: datetime
    event_id: str
    kind: str
    port: int | None
    username: str | None
    user_exists: bool | None


def _meta(raw: str) -> dict[str, Any]:
    try:
        data = json.loads(raw)
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def _count_attempts(rows: list[_Attempt]) -> list[_Attempt]:
    """Drop invalid-user events whose connection also produced a failed-login event."""
    failed = [r for r in rows if r.kind == FAILED]
    failed_ports = {r.port for r in failed if r.port is not None}
    kept: list[_Attempt] = []
    for r in rows:
        if r.kind == FAILED:
            kept.append(r)
        elif r.port is not None:
            if r.port not in failed_ports:
                kept.append(r)
        elif not any(abs((f.ts - r.ts).total_seconds()) <= _SAME_ATTEMPT_SECONDS for f in failed):
            kept.append(r)
    return kept


def _best_window(attempts: list[_Attempt], window: timedelta) -> list[_Attempt]:
    """The window (<= `window` long, inclusive) containing the most attempts; ties go to the
    latest. Two pointers over time-sorted attempts."""
    best: list[_Attempt] = []
    left = 0
    for right in range(len(attempts)):
        while attempts[right].ts - attempts[left].ts > window:
            left += 1
        if right - left + 1 >= len(best):
            best = attempts[left : right + 1]
    return best


class SshFailuresRule(Rule):
    rule_id = "SP-001"
    name = "Repeated SSH failures"
    description = (
        "At least N failed SSH authentication attempts from one source IP within a time window."
    )
    severity = Severity.HIGH

    def __init__(self, cfg: Config, scoring: ScoringSettings) -> None:
        self.cfg = cfg
        self._points = rule_weight(self.rule_id, scoring)

    @property
    def enabled(self) -> bool:
        return self.cfg.enabled

    @property
    def cooldown(self) -> timedelta:
        return timedelta(minutes=self.cfg.cooldown_minutes)

    def thresholds(self) -> dict[str, Any]:
        return {
            "threshold": self.cfg.threshold,
            "window_minutes": self.cfg.window_minutes,
            "cooldown_minutes": self.cfg.cooldown_minutes,
            "ignored_source_ips": self.cfg.ignored_source_ips,
        }

    def evaluate(self, conn: sqlite3.Connection, now: datetime) -> RuleResult:
        window = timedelta(minutes=self.cfg.window_minutes)
        # Look back two windows so a burst that ended between two evaluations is still seen.
        rows = conn.execute(
            "SELECT id, timestamp, event_type, source_ip, username, host, metadata_json"
            " FROM events WHERE source = ? AND event_type IN (?, ?) AND source_ip IS NOT NULL"
            " AND timestamp >= ? AND timestamp <= ? ORDER BY timestamp DESC, id DESC LIMIT ?",
            (
                EventSource.AUTH_LOG.value,
                FAILED,
                INVALID,
                to_db(now - 2 * window),
                to_db(now),
                MAX_ROWS + 1,
            ),
        ).fetchall()
        truncated = len(rows) > MAX_ROWS
        rows = list(reversed(rows[:MAX_ROWS]))

        by_ip: dict[str, list[_Attempt]] = {}
        hosts: dict[str, str] = {}
        for r in rows:
            if r["source_ip"] in self.cfg.ignored_source_ips:
                continue
            meta = _meta(r["metadata_json"])
            port = meta.get("src_port")
            by_ip.setdefault(r["source_ip"], []).append(
                _Attempt(
                    ts=from_db(r["timestamp"]),
                    event_id=r["id"],
                    kind=r["event_type"],
                    port=port if isinstance(port, int) else None,
                    username=r["username"],
                    user_exists=meta.get("user_exists")
                    if isinstance(meta.get("user_exists"), bool)
                    else None,
                )
            )
            hosts[r["source_ip"]] = r["host"]

        result = RuleResult(note="evidence query truncated at 10000 rows" if truncated else None)
        for ip in sorted(by_ip):
            attempts = _best_window(_count_attempts(by_ip[ip]), window)
            if len(attempts) < self.cfg.threshold:
                continue
            result.detections.append(self._detection(conn, ip, hosts[ip], attempts, now))
        return result

    def _detection(
        self,
        conn: sqlite3.Connection,
        ip: str,
        host: str,
        attempts: list[_Attempt],
        now: datetime,
    ) -> Detection:
        start, end = attempts[0].ts, attempts[-1].ts
        success = conn.execute(
            "SELECT 1 FROM events WHERE source = ? AND event_type = ? AND source_ip = ?"
            " AND timestamp >= ? AND timestamp <= ? LIMIT 1",
            (EventSource.AUTH_LOG.value, SUCCESS, ip, to_db(start), to_db(now)),
        ).fetchone()
        accounts = sorted({a.username for a in attempts if a.username})[:10]
        unknown = sum(1 for a in attempts if a.user_exists is False)
        n, cfg = len(attempts), self.cfg
        summary = f"SP-001: {n} failed SSH attempts from {ip} within {cfg.window_minutes} min"
        if success:
            summary += "; a successful login from this address followed"
        evidence = [a.event_id for a in attempts]
        metadata: dict[str, Any] = {
            "rule_id": self.rule_id,
            "rule_name": self.name,
            "trigger": f"at least {cfg.threshold} failed SSH attempts from one IP within "
            f"{cfg.window_minutes} minutes",
            "explanation": f"{n} failed SSH authentication attempts came from {ip} between "
            f"{to_db(start)} and {to_db(end)}, which meets the threshold of {cfg.threshold}.",
            "attempts": n,
            "threshold": cfg.threshold,
            "window_minutes": cfg.window_minutes,
            "window_start": to_db(start),
            "window_end": to_db(end),
            "unknown_user_attempts": unknown,
            "targeted_accounts": accounts,
            "login_after_failures": bool(success),
            "evidence_event_ids": evidence[:MAX_EVIDENCE],
            "evidence_truncated": len(evidence) > MAX_EVIDENCE,
            "dedupe_key": f"{self.rule_id}:{ip}",
            "risk_points": self._points,
        }
        event = Event(
            timestamp=now,
            source=EventSource.AUTH_LOG,
            event_type="detection.ssh_repeated_failures",
            severity=self.severity,
            summary=summary,
            source_ip=ip,
            host=host,
            metadata=metadata,
        )
        return Detection(self.rule_id, f"{self.rule_id}:{ip}", event)


def evidence_ids(event: Event) -> list[UUID]:
    """Evidence event IDs recorded on a detection event (used by Phase 6 correlation)."""
    raw = event.metadata.get("evidence_event_ids", [])
    out: list[UUID] = []
    for item in raw if isinstance(raw, list) else []:
        try:
            out.append(UUID(str(item)))
        except ValueError:
            continue
    return out
