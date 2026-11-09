"""The acknowledge button: physical access to the Pi is the only authentication.

Anyone standing at the Pi can press it. That is acceptable for a home lab, so every press is
written to the incident's audit trail with the actor "button".
"""

from __future__ import annotations

import logging
import sqlite3
from collections.abc import Callable
from datetime import datetime

from sentinelpi.incidents import lifecycle
from sentinelpi.incidents.models import Incident, IncidentStatus
from sentinelpi.storage import incidents_repo
from sentinelpi.storage.db import Database

log = logging.getLogger("sentinelpi.button")

NOTE = "Acknowledged with the physical button"


def acknowledge_top_alert(conn: sqlite3.Connection, now: datetime | None = None) -> Incident | None:
    """Acknowledge the incident the kiosk is showing: the most severe open one, newest first.

    One press, one incident: with two alerts open the next press clears the next one.
    Returns None when nothing is open (a press then does nothing)."""
    opened = incidents_repo.list_incidents(conn, status=IncidentStatus.OPEN, limit=50)
    if not opened:
        return None
    opened.sort(key=lambda i: (-i.severity.rank, -i.last_seen.timestamp()))
    try:
        return lifecycle.change_status(
            conn, opened[0].id, IncidentStatus.ACKNOWLEDGED, note=NOTE, actor="button", now=now
        )
    except lifecycle.TransitionError:  # someone acknowledged it on the dashboard a moment ago
        return None


def open_button(pin: int, on_press: Callable[[], None], hold_seconds: float = 0.5):
    """Wire the pin (to ground, internal pull-up) to `on_press`. The button must be held for
    `hold_seconds`, so a brush or a flicker on the wire cannot acknowledge anything."""
    from gpiozero import Button

    button = Button(pin, pull_up=True, bounce_time=0.05, hold_time=hold_seconds)
    button.when_held = on_press
    return button


def press_handler(db: Database, after: Callable[[], object] | None = None) -> Callable[[], None]:
    def handle() -> None:
        try:
            with db.session() as conn:
                done = acknowledge_top_alert(conn)
        except Exception:
            log.exception("button press could not be recorded")
            return
        if done is None:
            log.info("button pressed: no open incident to acknowledge")
            return
        log.info("button pressed: acknowledged %s", done.id)
        if after is not None:
            after()  # update the lights now instead of waiting for the next cycle

    return handle
