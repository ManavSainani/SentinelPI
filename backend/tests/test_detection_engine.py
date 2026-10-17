from datetime import timedelta

from sentinelpi.config import DetectionSettings
from sentinelpi.detection.base import Detection, Rule, RuleResult
from sentinelpi.detection.engine import DetectionEngine
from sentinelpi.events import Event, EventSource, Severity
from sentinelpi.storage import detection_repo, events_repo
from tests.conftest import NOW
from tests.helpers_detection import (
    burst,
    detection_events,
    engine,
    put_baseline,
    put_ports,
    put_processes,
)


def attack(conn, ip="203.0.113.9", n=6, ago=60):
    events_repo.insert_events(conn, burst(NOW - timedelta(seconds=ago), n, step_seconds=5, ip=ip))


def states(report):
    return {r.rule_id: r for r in report.rules}


def test_detection_is_stored_as_an_event_with_evidence(conn):
    attack(conn)
    report = engine().run(conn, NOW)
    assert states(report)["SP-001"].fired == 1 and report.events_created == 1
    stored = detection_events(conn, "detection.ssh_repeated_failures")
    assert len(stored) == 1 and stored[0].metadata["attempts"] == 6
    assert detection_repo.get_last_fired(conn, "SP-001:203.0.113.9") == NOW


def test_a_persistent_condition_does_not_spam(conn):
    attack(conn)
    eng = engine()
    # evaluate every 30 s for 20 minutes while the attack evidence stays visible
    fired = suppressed = 0
    for i in range(0, 20 * 60, 30):
        rep = eng.run(conn, NOW + timedelta(seconds=i))
        fired += states(rep)["SP-001"].fired
        suppressed += states(rep)["SP-001"].suppressed
    assert fired == 1  # one alert, not forty
    assert len(detection_events(conn)) == 1
    assert suppressed >= 1


def test_alert_returns_after_the_cooldown_when_the_attack_continues(conn):
    eng = engine()
    attack(conn, ago=60)
    eng.run(conn, NOW)
    later = NOW + timedelta(minutes=31)
    events_repo.insert_events(conn, burst(later - timedelta(seconds=40), 6, step_seconds=5))
    rep = eng.run(conn, later)
    assert states(rep)["SP-001"].fired == 1 and len(detection_events(conn)) == 2


def test_inside_the_cooldown_new_evidence_is_still_suppressed(conn):
    eng = engine()
    attack(conn, ago=60)
    eng.run(conn, NOW)
    soon = NOW + timedelta(minutes=10)
    events_repo.insert_events(conn, burst(soon - timedelta(seconds=40), 8, step_seconds=5))
    assert states(eng.run(conn, soon))["SP-001"].suppressed == 1
    assert len(detection_events(conn)) == 1


def test_different_sources_have_independent_cooldowns(conn):
    attack(conn, ip="203.0.113.1")
    attack(conn, ip="203.0.113.2")
    rep = engine().run(conn, NOW)
    assert states(rep)["SP-001"].fired == 2


def test_cooldown_is_configurable(conn):
    attack(conn)
    eng = engine(ssh_failures={"cooldown_minutes": 1})
    eng.run(conn, NOW)
    events_repo.insert_events(conn, burst(NOW + timedelta(minutes=2), 6, step_seconds=1))
    assert states(eng.run(conn, NOW + timedelta(minutes=3)))["SP-001"].fired == 1


def test_disabled_rules_do_nothing(conn):
    attack(conn)
    rep = engine(ssh_failures={"enabled": False}).run(conn, NOW)
    assert states(rep)["SP-001"].state == "disabled" and detection_events(conn) == []


def test_skipped_rules_say_why(conn):
    rep = engine().run(conn, NOW)
    s = states(rep)
    assert s["SP-002"].state == "skipped" and "baseline" in s["SP-002"].detail
    assert s["SP-003"].state == "skipped" and s["SP-004"].state == "skipped"
    assert s["SP-001"].state == "ok"


class Broken(Rule):
    rule_id, name, description, severity = "SP-X", "Broken", "boom", Severity.LOW
    enabled = True
    cooldown = timedelta(minutes=1)

    def thresholds(self):
        return {}

    def evaluate(self, conn, now):
        raise RuntimeError("/secret/path")


def test_a_failing_rule_is_isolated_and_reports_type_only(conn):
    attack(conn)
    eng = DetectionEngine(DetectionSettings())
    eng.rules.insert(0, Broken())
    rep = eng.run(conn, NOW)
    s = states(rep)
    assert s["SP-X"].state == "error" and s["SP-X"].detail == "RuntimeError"
    assert s["SP-001"].fired == 1  # later rules still ran


class Fixed(Rule):
    rule_id, name, description, severity = "SP-Y", "Fixed", "dup", Severity.LOW
    enabled = True
    cooldown = timedelta(minutes=1)

    def __init__(self, event):
        self.event = event

    def thresholds(self):
        return {}

    def evaluate(self, conn, now):
        return RuleResult(detections=[Detection("SP-Y", "SP-Y:k", self.event)])


def test_event_and_cooldown_record_are_written_together_or_not_at_all(conn):
    ev = Event(
        timestamp=NOW,
        source=EventSource.TEST,
        event_type="detection.x",
        severity=Severity.LOW,
        summary="s",
        host="h",
    )
    events_repo.insert_event(conn, ev)  # same id already exists -> insert will fail
    eng = DetectionEngine(DetectionSettings(), rules=[Fixed(ev)])
    rep = eng.run(conn, NOW)
    assert states(rep)["SP-Y"].state == "error"
    assert detection_repo.get_last_fired(conn, "SP-Y:k") is None  # no half-written state
    assert events_repo.count_events(conn) == 1


def test_rule_catalog_is_mirrored_into_detection_rules(conn):
    engine().run(conn, NOW)
    rows = {r["id"]: r for r in conn.execute("SELECT * FROM detection_rules")}
    assert set(rows) == {"SP-001", "SP-002", "SP-003", "SP-004"}
    assert rows["SP-001"]["severity"] == "high" and rows["SP-001"]["enabled"] == 1
    assert '"threshold":5' in rows["SP-001"]["threshold_json"]
    engine(cpu={"enabled": False}, ssh_failures={"threshold": 9}).run(conn, NOW)
    rows = {r["id"]: r for r in conn.execute("SELECT * FROM detection_rules")}
    assert rows["SP-003"]["enabled"] == 0 and '"threshold":9' in rows["SP-001"]["threshold_json"]


def test_all_four_rules_fire_together(conn):
    from sentinelpi.storage import telemetry_repo
    from tests.helpers_detection import cpu_series

    attack(conn)
    put_baseline(conn, NOW - timedelta(days=1), [("tcp", 22, "0.0.0.0", "sshd")])
    put_ports(
        conn,
        NOW - timedelta(seconds=20),
        [("tcp", 22, "0.0.0.0", "sshd"), ("tcp", 4444, "0.0.0.0", "nc")],
    )
    put_processes(conn, NOW - timedelta(seconds=20), [(7, "xmrig", "pi", 99.0, 5.0)])
    telemetry_repo.insert_metrics_many(conn, cpu_series(NOW, 99.5))
    rep = engine().run(conn, NOW)
    assert {r.rule_id: r.fired for r in rep.rules} == {
        "SP-001": 1,
        "SP-002": 1,
        "SP-003": 1,
        "SP-004": 1,
    }
    types = {e.event_type for e in detection_events(conn)}
    assert types == {
        "detection.ssh_repeated_failures",
        "detection.new_listening_port",
        "detection.sustained_high_cpu",
        "detection.watchlisted_process",
    }
    assert all(
        e.metadata["rule_id"].startswith("SP-") and e.metadata["explanation"]
        for e in detection_events(conn)
    )
