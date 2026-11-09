"""Shared freshness rules, so the API, the kiosk and the status LEDs always agree."""

from __future__ import annotations

from sentinelpi.config import Settings


def monitor_running(age_seconds: float | None, settings: Settings) -> bool:
    """Alive if it reported within three detection cycles (plus slack for a slow cycle)."""
    return (
        age_seconds is not None
        and age_seconds <= 3 * settings.monitor.detection_interval_seconds + 15
    )


def metrics_stale(age_seconds: float, settings: Settings) -> bool:
    return age_seconds > max(30, 3 * settings.monitor.metrics_interval_seconds)
