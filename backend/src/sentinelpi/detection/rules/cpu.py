"""SP-003: CPU stays strictly above a threshold for a whole sustained window.

"Sustained" must be proven by data: the window needs enough samples with no large gaps, so a
monitor that was stopped or a few lucky samples can never produce (or hide) an alert. If the
window is not fully covered the rule is skipped, not guessed. Exactly-at-threshold is not
"above". Severity is Low, or Medium when the average is at least `high_cpu_percent`.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta
from typing import Any

from sentinelpi.config import CpuRule as Config
from sentinelpi.config import ScoringSettings
from sentinelpi.detection.base import Detection, Rule, RuleResult
from sentinelpi.detection.scoring import rule_weight
from sentinelpi.events import Event, EventSource, Severity
from sentinelpi.timeutil import from_db, to_db

MAX_SAMPLES = 5000


class CpuRule(Rule):
    rule_id = "SP-003"
    name = "Sustained high CPU"
    description = "CPU usage stays above a threshold for a sustained window."
    severity = Severity.LOW  # raised to Medium when the average is very high

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
        c = self.cfg
        return {
            "cpu_percent": c.cpu_percent,
            "window_minutes": c.window_minutes,
            "min_samples": c.min_samples,
            "max_gap_seconds": c.max_gap_seconds,
            "high_cpu_percent": c.high_cpu_percent,
            "cooldown_minutes": c.cooldown_minutes,
        }

    def evaluate(self, conn: sqlite3.Connection, now: datetime) -> RuleResult:
        cfg = self.cfg
        window = timedelta(minutes=cfg.window_minutes)
        start = now - window
        rows = conn.execute(
            "SELECT timestamp, cpu_percent FROM system_metrics WHERE timestamp >= ?"
            " AND timestamp <= ? ORDER BY timestamp ASC LIMIT ?",
            (to_db(start), to_db(now), MAX_SAMPLES),
        ).fetchall()
        samples = [(from_db(r["timestamp"]), float(r["cpu_percent"])) for r in rows]
        if len(samples) < cfg.min_samples:
            return RuleResult(
                skipped_reason=f"only {len(samples)} samples in the window "
                f"(need {cfg.min_samples})"
            )
        gap = timedelta(seconds=cfg.max_gap_seconds)
        times = [t for t, _ in samples]
        covered = (
            times[0] - start <= gap
            and now - times[-1] <= gap
            and all(b - a <= gap for a, b in zip(times, times[1:], strict=False))
        )
        if not covered:
            return RuleResult(skipped_reason="samples do not cover the whole window")

        values = [v for _, v in samples]
        if not all(v > cfg.cpu_percent for v in values):
            return RuleResult()
        avg = sum(values) / len(values)
        severity = Severity.MEDIUM if avg >= cfg.high_cpu_percent else Severity.LOW
        metadata: dict[str, Any] = {
            "rule_id": self.rule_id,
            "rule_name": self.name,
            "trigger": f"CPU above {cfg.cpu_percent:g}% for {cfg.window_minutes} minutes",
            "explanation": f"All {len(values)} CPU samples between {to_db(times[0])} and "
            f"{to_db(times[-1])} were above {cfg.cpu_percent:g}%.",
            "cpu_threshold": cfg.cpu_percent,
            "window_minutes": cfg.window_minutes,
            "samples": len(values),
            "cpu_avg": round(avg, 1),
            "cpu_min": round(min(values), 1),
            "cpu_max": round(max(values), 1),
            "window_start": to_db(times[0]),
            "window_end": to_db(times[-1]),
            "dedupe_key": f"{self.rule_id}:cpu",
            "risk_points": self._points,
        }
        event = Event(
            timestamp=now,
            source=EventSource.SYSTEM_METRICS,
            event_type="detection.sustained_high_cpu",
            severity=severity,
            summary=f"SP-003: CPU above {cfg.cpu_percent:g}% for {cfg.window_minutes} min "
            f"(average {avg:.1f}%)",
            metadata=metadata,
        )
        return RuleResult(detections=[Detection(self.rule_id, f"{self.rule_id}:cpu", event)])
