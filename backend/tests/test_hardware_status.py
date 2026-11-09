from datetime import timedelta

import pytest
from gpiozero import Device
from gpiozero.pins.mock import MockFactory

from sentinelpi.collectors.metrics import MetricsSample
from sentinelpi.config import HardwareSettings, Settings
from sentinelpi.hardware import open_panel
from sentinelpi.hardware.status import HEALTHY, StatusLoop, led_state
from sentinelpi.incidents import lifecycle
from sentinelpi.incidents.models import IncidentStatus
from sentinelpi.monitor import HEARTBEAT_KEY
from sentinelpi.storage import incidents_repo, state_repo, telemetry_repo
from sentinelpi.timeutil import to_db, utc_now
from tests.helpers_incidents import correlator, detection, put

S = Settings()


def beat(conn, now, age=0.0):
    state_repo.set_state(conn, HEARTBEAT_KEY, to_db(now - timedelta(seconds=age)))


def incident(conn, now, rule="SP-001", severity=None):
    put(
        conn,
        detection(now, rule, ip="203.0.113.9" if rule == "SP-001" else None, severity=severity),
    )
    correlator().run(conn, now)
    return incidents_repo.list_incidents(conn, limit=50)[0]


def state(db, now):
    with db.session() as c:
        return led_state(c, S, now)


def test_quiet_and_healthy_is_green(db):
    now = utc_now()
    with db.session() as c:
        beat(c, now)
    assert state(db, now) == HEALTHY


def test_no_heartbeat_ever_is_yellow(db):
    s = state(db, utc_now())
    assert s.yellow and not s.green and "not running" in s.reason


def test_a_silent_monitor_is_yellow(db):
    now = utc_now()
    with db.session() as c:
        beat(c, now, age=600)
    assert state(db, now).yellow


def test_stale_metrics_are_yellow(db):
    now = utc_now()
    with db.session() as c:
        beat(c, now)
        telemetry_repo.insert_metrics(
            c,
            MetricsSample(
                timestamp=now - timedelta(minutes=10),
                cpu_percent=1,
                memory_percent=1,
                disk_percent=1,
                temperature_c=None,
                uptime_seconds=1,
            ),
        )
    s = state(db, now)
    assert s.yellow and "out of date" in s.reason


def test_open_medium_incident_is_yellow_not_red(db):
    now = utc_now()
    with db.session() as c:
        beat(c, now)
        incident(c, now, "SP-002")
    s = state(db, now)
    assert s.yellow and not s.red and not s.green


def test_open_high_incident_blinks_red(db):
    now = utc_now()
    with db.session() as c:
        beat(c, now)
        incident(c, now, "SP-001")
    s = state(db, now)
    assert s.red and s.blink_red and not s.green and not s.yellow


def test_acknowledging_makes_red_steady_then_resolving_makes_it_green(db):
    now = utc_now()
    with db.session() as c:
        beat(c, now)
        inc = incident(c, now, "SP-001")
        lifecycle.change_status(c, inc.id, IncidentStatus.ACKNOWLEDGED)
    s = state(db, now)
    assert s.red and not s.blink_red
    with db.session() as c:
        lifecycle.change_status(c, inc.id, IncidentStatus.RESOLVED)
    assert state(db, now) == HEALTHY


def test_red_outranks_everything_else(db):
    now = utc_now()  # no heartbeat (would be yellow) and an open High incident
    with db.session() as c:
        incident(c, now, "SP-001")
    assert state(db, now).blink_red


def test_a_high_incident_is_not_hidden_by_many_low_ones(db):
    now = utc_now()
    with db.session() as c:
        beat(c, now)
        for i in range(60):
            put(c, detection(now - timedelta(hours=30 * i), "SP-003"))
        correlator().run(c, now)
        incident(c, now, "SP-001")
    assert state(db, now).blink_red


@pytest.fixture
def mock_pins():
    old = Device.pin_factory
    Device.pin_factory = MockFactory()
    yield Device.pin_factory
    Device.pin_factory.reset()
    Device.pin_factory = old


def test_loop_drives_the_pins_and_reports_a_database_failure_as_yellow(db, mock_pins):
    s = Settings(hardware=HardwareSettings(enabled=True))
    h = s.hardware
    panel, _ = open_panel(h)
    loop = StatusLoop(db, s, panel)
    now = utc_now()
    with db.session() as c:
        beat(c, now)
    loop.step(now)
    assert mock_pins.pin(h.green_led_pin).state == 1
    with db.session() as c:
        incident(c, now, "SP-001")
    loop.step(now)
    assert mock_pins.pin(h.green_led_pin).state == 0
    assert mock_pins.pin(h.red_led_pin).state in (0, 1)  # blinking: either phase is fine
    db.path.unlink()
    for suffix in ("-wal", "-shm"):
        (db.path.parent / (db.path.name + suffix)).unlink(missing_ok=True)
    # the connection fails or sees an empty file; either way the lights must not claim "green"
    got = loop.step(now)
    assert not got.green
    panel.close()
