import sqlite3
from datetime import timedelta

import pytest
from gpiozero import Device
from gpiozero.pins.mock import MockFactory

from sentinelpi.config import HardwareSettings, Settings
from sentinelpi.events import Severity
from sentinelpi.hardware import open_panel
from sentinelpi.hardware.button import NOTE, acknowledge_top_alert, open_button, press_handler
from sentinelpi.hardware.status import StatusLoop
from sentinelpi.incidents.models import IncidentStatus
from sentinelpi.storage import incidents_repo
from sentinelpi.timeutil import utc_now
from tests.helpers_incidents import correlator, detection, put


def make(conn, now, rule, ip=None):
    put(conn, detection(now, rule, ip=ip))
    correlator().run(conn, now)


def statuses(conn):
    return {i.title: i.status for i in incidents_repo.list_incidents(conn, limit=50)}


def test_nothing_open_means_a_press_does_nothing(db):
    with db.session() as c:
        assert acknowledge_top_alert(c) is None


def test_press_acknowledges_the_most_severe_open_incident_and_audits_it(db):
    now = utc_now()
    with db.session() as c:
        make(c, now - timedelta(minutes=5), "SP-002")  # medium, older
        make(c, now, "SP-001", ip="203.0.113.9")  # high
        done = acknowledge_top_alert(c)
        assert done is not None and done.severity == Severity.HIGH
        assert done.status == IncidentStatus.ACKNOWLEDGED
        trail = incidents_repo.get_timeline(c, done.id)
        change = [t for t in trail if t.audit_kind == "status_changed"][-1]
        assert change.actor == "button" and change.note == NOTE


def test_each_press_clears_one_incident_in_severity_order(db):
    now = utc_now()
    with db.session() as c:
        make(c, now, "SP-002")
        make(c, now, "SP-001", ip="203.0.113.9")
        first = acknowledge_top_alert(c)
        second = acknowledge_top_alert(c)
        third = acknowledge_top_alert(c)
    assert first.severity.rank > second.severity.rank
    assert third is None


def test_an_already_acknowledged_incident_is_left_alone(db):
    now = utc_now()
    with db.session() as c:
        make(c, now, "SP-001", ip="203.0.113.9")
        assert acknowledge_top_alert(c) is not None
        assert acknowledge_top_alert(c) is None


def test_old_audit_rows_survive_and_the_new_actor_is_accepted(db):
    # the migration rebuilt incident_audit; its CHECK must allow 'button' and still refuse others
    with db.session() as c:
        make(c, utc_now(), "SP-001", ip="203.0.113.9")
        before = c.execute("SELECT COUNT(*) FROM incident_audit").fetchone()[0]
        acknowledge_top_alert(c)
        assert c.execute("SELECT COUNT(*) FROM incident_audit").fetchone()[0] == before + 1
        with pytest.raises(sqlite3.IntegrityError):
            c.execute(
                "INSERT INTO incident_audit (incident_id, at, kind, actor)"
                " SELECT id, 'x', 'created', 'stranger' FROM incidents LIMIT 1"
            )


@pytest.fixture
def mock_pins():
    old = Device.pin_factory
    Device.pin_factory = MockFactory()
    yield Device.pin_factory
    Device.pin_factory.reset()
    Device.pin_factory = old


def test_a_held_press_acknowledges_and_updates_the_lights(db, mock_pins):
    s = Settings(hardware=HardwareSettings(enabled=True))
    h = s.hardware
    panel, _ = open_panel(h)
    loop = StatusLoop(db, s, panel)
    now = utc_now()
    with db.session() as c:
        make(c, now, "SP-001", ip="203.0.113.9")
    loop.step(now)
    button = open_button(h.button_pin, press_handler(db, after=loop.step), hold_seconds=0.05)
    pin = mock_pins.pin(h.button_pin)
    pin.drive_low()  # pressed (wired to ground)
    import time

    time.sleep(0.4)
    pin.drive_high()
    with db.session() as c:
        assert list(statuses(c).values()) == [IncidentStatus.ACKNOWLEDGED]
    assert mock_pins.pin(h.red_led_pin).state == 1  # steady red now, not blinking
    button.close()
    panel.close()


def test_a_brief_tap_is_ignored(db, mock_pins):
    h = HardwareSettings()
    with db.session() as c:
        make(c, utc_now(), "SP-001", ip="203.0.113.9")
    button = open_button(h.button_pin, press_handler(db), hold_seconds=0.5)
    pin = mock_pins.pin(h.button_pin)
    pin.drive_low()
    import time

    time.sleep(0.1)
    pin.drive_high()
    time.sleep(0.6)
    with db.session() as c:
        assert list(statuses(c).values()) == [IncidentStatus.OPEN]
    button.close()
