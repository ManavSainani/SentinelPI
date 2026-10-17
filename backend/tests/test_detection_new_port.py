from datetime import timedelta

import pytest

from sentinelpi.config import NewPortRule as Cfg
from sentinelpi.config import ScoringSettings
from sentinelpi.detection.rules.new_port import NewPortRule, is_exposed
from sentinelpi.events import EventSource, Severity
from tests.conftest import NOW
from tests.helpers_detection import put_baseline, put_ports

SNAP = NOW - timedelta(seconds=30)
BASE = [("tcp", 22, "0.0.0.0", "sshd"), ("tcp", 8787, "127.0.0.1", "python3")]


def rule(**kw):
    return NewPortRule(Cfg(**kw), ScoringSettings(), timedelta(minutes=10))


def setup(conn, current, baseline=BASE, protocols=("tcp", "udp")):
    put_baseline(conn, NOW - timedelta(days=1), baseline, protocols)
    put_ports(conn, SNAP, current)


def test_skipped_until_a_baseline_exists(conn):
    put_ports(conn, SNAP, BASE)
    res = rule().evaluate(conn, NOW)
    assert "no baseline" in res.skipped_reason and res.detections == []


def test_skipped_without_a_snapshot(conn):
    put_baseline(conn, NOW, BASE)
    assert "no port snapshot" in rule().evaluate(conn, NOW).skipped_reason


def test_stale_snapshot_is_not_judged(conn):
    put_baseline(conn, NOW, BASE)
    put_ports(conn, NOW - timedelta(minutes=11), BASE + [("tcp", 4444, "0.0.0.0", "nc")])
    assert "stale" in rule().evaluate(conn, NOW).skipped_reason


def test_negative_nothing_new(conn):
    setup(conn, BASE)
    assert rule().evaluate(conn, NOW).detections == []


def test_ports_that_disappeared_are_not_alerts(conn):
    setup(conn, [("tcp", 22, "0.0.0.0", "sshd")])
    assert rule().evaluate(conn, NOW).detections == []


def test_positive_new_tcp_port(conn):
    setup(conn, BASE + [("tcp", 4444, "0.0.0.0", "nc")])
    res = rule().evaluate(conn, NOW)
    assert len(res.detections) == 1
    d = res.detections[0]
    e = d.event
    assert d.dedupe_key == "SP-002:tcp/4444" and e.severity == Severity.MEDIUM
    assert e.source == EventSource.PORT_INVENTORY and e.process_name == "nc"
    assert e.event_type == "detection.new_listening_port"
    assert e.metadata["port"] == 4444 and e.metadata["exposed"] is True
    assert e.metadata["risk_points"] == 20 and e.metadata["rule_id"] == "SP-002"
    assert "reachable beyond loopback" in e.summary and "(nc)" in e.summary


def test_loopback_only_listener_is_labelled_as_such(conn):
    setup(conn, BASE + [("tcp", 9999, "127.0.0.1", None)])
    e = rule().evaluate(conn, NOW).detections[0].event
    assert (
        e.metadata["exposed"] is False and "loopback only" in e.summary and e.process_name is None
    )


@pytest.mark.parametrize(
    "addr,exposed",
    [
        ("127.0.0.1", False),
        ("::1", False),
        ("localhost", False),
        ("*", True),
        ("0.0.0.0", True),
        ("::", True),
        ("192.168.4.20", True),
        ("garbage", True),
    ],
)
def test_exposure(addr, exposed):
    assert is_exposed(addr) is exposed


def test_same_port_on_two_addresses_is_one_detection(conn):
    setup(conn, BASE + [("tcp", 5000, "0.0.0.0", "x"), ("tcp", 5000, "::", "x")])
    res = rule().evaluate(conn, NOW)
    assert len(res.detections) == 1 and res.detections[0].event.metadata["local_addresses"] == [
        "0.0.0.0",
        "::",
    ]


def test_protocol_is_part_of_the_key(conn):
    setup(conn, BASE + [("udp", 22, "0.0.0.0", "x")])  # tcp/22 is known, udp/22 is not
    keys = [d.dedupe_key for d in rule().evaluate(conn, NOW).detections]
    assert keys == ["SP-002:udp/22"]


def test_protocols_the_baseline_could_not_see_are_not_compared(conn):
    # baseline taken in the macOS TCP-only mode; a later full snapshot shows UDP listeners
    setup(conn, BASE + [("udp", 5353, "0.0.0.0", "mdns")], protocols=("tcp",))
    assert rule().evaluate(conn, NOW).detections == []


def test_configured_protocols_limit_the_rule(conn):
    setup(conn, BASE + [("udp", 5353, "0.0.0.0", "mdns"), ("tcp", 81, "0.0.0.0", "x")])
    keys = [d.dedupe_key for d in rule(protocols=["tcp"]).evaluate(conn, NOW).detections]
    assert keys == ["SP-002:tcp/81"]


def test_ignored_ports(conn):
    setup(conn, BASE + [("udp", 5353, "0.0.0.0", "avahi"), ("tcp", 81, "0.0.0.0", "x")])
    keys = [d.dedupe_key for d in rule(ignored_ports=["udp/5353"]).evaluate(conn, NOW).detections]
    assert keys == ["SP-002:tcp/81"]


def test_flood_of_new_ports_is_capped_and_reported(conn):
    setup(conn, BASE + [("tcp", 20000 + i, "0.0.0.0", None) for i in range(30)])
    res = rule(max_per_run=5).evaluate(conn, NOW)
    assert len(res.detections) == 5 and "30 new ports" in res.note


def test_only_the_latest_snapshot_counts(conn):
    put_baseline(conn, NOW - timedelta(days=1), BASE)
    put_ports(conn, NOW - timedelta(minutes=5), BASE + [("tcp", 4444, "0.0.0.0", "nc")])
    put_ports(conn, SNAP, BASE)  # the port is gone again
    assert rule().evaluate(conn, NOW).detections == []


@pytest.mark.parametrize("bad", [["tcp/0"], ["tcp/70000"], ["http/80"], ["80"], ["tcp/8080; DROP"]])
def test_ignored_ports_validation(bad):
    with pytest.raises(ValueError):
        Cfg(ignored_ports=bad)
