"""Work out what the status LEDs should show, straight from the database.

This deliberately does not go through the web API: the lights keep working when the
dashboard or the browser is down.
"""

from __future__ import annotations

import logging
import signal
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime

from sentinelpi.config import Settings
from sentinelpi.events import Severity
from sentinelpi.hardware.button import open_button, press_handler
from sentinelpi.hardware.leds import LedPanel, open_panel
from sentinelpi.health import metrics_stale, monitor_running
from sentinelpi.incidents.models import IncidentStatus
from sentinelpi.monitor import HEARTBEAT_KEY
from sentinelpi.storage import incidents_repo, state_repo, telemetry_repo
from sentinelpi.storage.db import Database
from sentinelpi.timeutil import from_db, utc_now

log = logging.getLogger("sentinelpi.leds")


@dataclass(frozen=True)
class LedState:
    green: bool = False
    yellow: bool = False
    red: bool = False
    blink_red: bool = False
    reason: str = ""


# What each light means. One state at a time, so the lights can never contradict each other.
HEALTHY = LedState(green=True, reason="healthy")
UNKNOWN = LedState(yellow=True, reason="cannot read the database")


def led_state(conn: sqlite3.Connection, settings: Settings, now: datetime) -> LedState:
    """Red blinking: an open High or Critical incident nobody has acknowledged.
    Red steady: High or Critical incidents exist but all are acknowledged.
    Yellow: an open Low or Medium incident, a monitor that has gone quiet, or stale metrics.
    Green: none of the above."""

    def any_incident(status: IncidentStatus, floor: Severity | None = None) -> bool:
        return bool(incidents_repo.list_incidents(conn, status=status, min_severity=floor, limit=1))

    if any_incident(IncidentStatus.OPEN, Severity.HIGH):
        return LedState(red=True, blink_red=True, reason="open High or Critical incident")
    if any_incident(IncidentStatus.ACKNOWLEDGED, Severity.HIGH):
        return LedState(red=True, reason="High or Critical incident acknowledged, not resolved")
    if any_incident(IncidentStatus.OPEN):
        return LedState(yellow=True, reason="open Low or Medium incident")
    raw = state_repo.get_state(conn, HEARTBEAT_KEY)
    age = None if raw is None else max(0.0, (now - from_db(raw)).total_seconds())
    if not monitor_running(age, settings):
        return LedState(yellow=True, reason="the monitor is not running")
    sample = telemetry_repo.latest_metrics(conn)
    if sample is not None and metrics_stale(
        max(0.0, (now - sample.timestamp).total_seconds()), settings
    ):
        return LedState(yellow=True, reason="system metrics are out of date")
    return HEALTHY


class StatusLoop:
    """Polls the database and drives the panel. `step` is one cycle, so tests need no threads."""

    def __init__(self, db: Database, settings: Settings, panel: LedPanel) -> None:
        self._db, self._settings, self._panel = db, settings, panel
        self._shown: LedState | None = None
        self._lock = threading.Lock()  # the button thread and the polling loop both call step

    def step(self, now: datetime | None = None) -> LedState:
        with self._lock:
            return self._step(now)

    def _step(self, now: datetime | None) -> LedState:
        try:
            with self._db.session() as conn:
                state = led_state(conn, self._settings, now or utc_now())
        except Exception:  # a locked or missing database must never leave the lights lying
            log.exception("could not read the database")
            state = UNKNOWN
        if state != self._shown:  # re-applying would restart the blink every cycle
            log.info("LEDs: %s", state.reason)
            self._panel.show(
                green=state.green, yellow=state.yellow, red=state.red, blink_red=state.blink_red
            )
            self._shown = state
        return state

    def run(self, stop: threading.Event, interval: float = 2.0) -> None:
        while not stop.is_set():
            self.step()
            stop.wait(interval)


def run_service(settings: Settings) -> int:
    """Entry point for the systemd unit."""
    if not settings.hardware.enabled:
        print("hardware is disabled in the configuration ([hardware] enabled = false)")
        return 0
    panel, why = open_panel(settings.hardware)
    if panel is None:
        print(f"cannot use the LEDs: {why}")
        return 1
    stop = threading.Event()
    button = None
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    try:
        panel.show(green=True, yellow=True, red=True)  # one second of "all on" proves the wiring
        stop.wait(1.0)
        db = Database(settings.storage.db_path)
        loop = StatusLoop(db, settings, panel)
        try:
            button = open_button(settings.hardware.button_pin, press_handler(db, after=loop.step))
        except Exception as exc:  # no button must never stop the lights
            log.warning("acknowledge button unavailable: %s", exc)
        loop.run(stop)
    finally:
        if button is not None:
            button.close()
        panel.close()
    return 0
