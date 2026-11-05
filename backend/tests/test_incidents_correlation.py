from datetime import timedelta

import pytest
from pydantic import ValidationError

from sentinelpi.config import IncidentSettings, RetentionSettings
from sentinelpi.events import Severity
from sentinelpi.incidents.models import IncidentStatus
from sentinelpi.storage import events_repo, incidents_repo, retention
from tests.conftest import NOW
from tests.helpers_detection import auth_event, burst, engine
from tests.helpers_incidents import correlator, detection, put

IP = "203.0.113.9"


def all_incidents(conn):
    return incidents_repo.list_incidents(conn, limit=500)


def audit_kinds(conn, incident_id):
    timeline = incidents_repo.get_timeline(conn, incident_id)
    return [i.audit_kind for i in timeline if i.kind == "audit"]


# ------------------------------------------------------------------ creating incidents
def test_ssh_detection_opens_an_incident_with_its_evidence(conn):
    evidence = burst(NOW - timedelta(minutes=2), 6, ip=IP)
    put(conn, *evidence)
    det = detection(NOW, "SP-001", ip=IP, evidence=[e.id for e in evidence])
    put(conn, det)

    report = correlator().run(conn, NOW)

    assert (report.created, report.attached, report.examined) == (1, 0, 1)
    (inc,) = all_incidents(conn)
    assert inc.status is IncidentStatus.OPEN
    assert inc.severity is Severity.HIGH and inc.risk_score == 35
    assert inc.host == "pi" and inc.source_ip == IP and inc.rule_ids == ["SP-001"]
    assert inc.title == f"Repeated SSH failures from {IP}"
    assert inc.evidence_count == 7  # the detection plus its six attempts
    assert inc.first_seen == evidence[0].timestamp and inc.last_seen == NOW
    # every piece of evidence is linked, and the events' own rows are untouched
    assert events_repo.get_event(conn, evidence[0].id) == evidence[0]
    row = conn.execute("SELECT incident_id FROM events WHERE id = ?", (str(evidence[0].id),))
    assert row.fetchone()[0] == inc.id
    assert audit_kinds(conn, inc.id) == ["created"]


def test_correlation_is_idempotent(conn):
    put(conn, detection(NOW, ip=IP))
    c = correlator()
    c.run(conn, NOW)
    second = c.run(conn, NOW + timedelta(seconds=30))
    assert (second.examined, second.created, second.attached) == (0, 0, 0)
    assert len(all_incidents(conn)) == 1


def test_evidence_missing_from_the_database_is_ignored(conn):
    put(conn, detection(NOW, ip=IP, evidence=[__import__("uuid").uuid4()]))
    report = correlator().run(conn, NOW)
    assert report.created == 1 and report.errors == 0
    assert all_incidents(conn)[0].evidence_count == 1


# ------------------------------------------------------------------ grouping
def test_repeat_detections_from_the_same_ip_join_one_incident(conn):
    first, second = detection(NOW, ip=IP), detection(NOW + timedelta(minutes=30), ip=IP)
    put(conn, first)
    c = correlator()
    c.run(conn, NOW)
    put(conn, second)
    report = c.run(conn, NOW + timedelta(minutes=30))
    assert (report.created, report.attached) == (0, 1)  # exactly the window: inclusive
    (inc,) = all_incidents(conn)
    assert inc.last_seen == NOW + timedelta(minutes=30) and inc.evidence_count == 2
    assert inc.risk_score == 35  # same rule again does not add points
    assert audit_kinds(conn, inc.id) == ["created", "evidence_added"]


def test_a_gap_longer_than_the_window_starts_a_new_incident(conn):
    put(conn, detection(NOW, ip=IP))
    c = correlator()
    c.run(conn, NOW)
    later = NOW + timedelta(minutes=31)
    put(conn, detection(later, ip=IP))
    c.run(conn, later)
    assert len(all_incidents(conn)) == 2


def test_different_ips_and_different_hosts_never_merge(conn):
    put(
        conn,
        detection(NOW, ip=IP),
        detection(NOW, ip="203.0.113.77"),
        detection(NOW, ip=IP, host="other-pi"),
    )
    correlator().run(conn, NOW)
    assert len(all_incidents(conn)) == 3


def test_a_long_running_condition_eventually_starts_a_fresh_incident(conn):
    c = correlator(max_incident_hours=2)
    t = NOW
    for _ in range(9):  # a detection every 20 minutes for 160 minutes
        put(conn, detection(t, ip=IP))
        c.run(conn, t)
        t += timedelta(minutes=20)
    incidents = all_incidents(conn)
    assert len(incidents) == 2
    oldest = min(incidents, key=lambda i: i.first_seen)
    assert oldest.last_seen - oldest.first_seen <= timedelta(hours=2)


def test_ip_incidents_and_host_local_incidents_stay_separate(conn):
    put(conn, detection(NOW, "SP-001", ip=IP), detection(NOW, "SP-002"))
    correlator().run(conn, NOW)
    incidents = all_incidents(conn)
    assert {i.source_ip for i in incidents} == {IP, None}


# ------------------------------------------------------------------ SP-005 and score
def test_two_different_rules_on_the_host_escalate_to_one_high_incident(conn):
    put(conn, detection(NOW, "SP-002"))
    c = correlator()
    c.run(conn, NOW)
    (inc,) = all_incidents(conn)
    assert inc.severity is Severity.MEDIUM and inc.risk_score == 20

    later = NOW + timedelta(minutes=5)
    put(conn, detection(later, "SP-004"))
    report = c.run(conn, later)

    assert (report.attached, report.escalated) == (1, 1)
    (inc,) = all_incidents(conn)
    assert inc.rule_ids == ["SP-002", "SP-004"]
    assert inc.severity is Severity.HIGH  # SP-005
    assert inc.risk_score == 20 + 30 + 10  # weights plus the independent-rule bonus
    assert [c["points"] for c in inc.risk_breakdown] == [20, 30, 10]
    assert inc.title == "Repeated suspicious activity on pi"
    assert "SP-002 New listening port" in inc.description and "SP-004" in inc.description
    assert audit_kinds(conn, inc.id) == ["created", "evidence_added", "escalated"]


def test_escalation_is_recorded_once(conn):
    c = correlator()
    for minutes, rule in ((0, "SP-002"), (1, "SP-004"), (2, "SP-003"), (3, "SP-004")):
        t = NOW + timedelta(minutes=minutes)
        put(conn, detection(t, rule))
        c.run(conn, t)
    (inc,) = all_incidents(conn)
    assert audit_kinds(conn, inc.id).count("escalated") == 1
    assert inc.risk_score == 20 + 30 + 10 + 20  # three distinct rules: two bonuses
    assert inc.rule_ids == ["SP-002", "SP-003", "SP-004"]


def test_the_escalation_threshold_is_configurable(conn):
    c = correlator(escalate_distinct_rules=3)
    put(conn, detection(NOW, "SP-002"), detection(NOW, "SP-004"))
    c.run(conn, NOW)
    (inc,) = all_incidents(conn)
    assert inc.severity is Severity.MEDIUM and inc.title == "Suspicious activity on pi"
    assert "escalated" not in audit_kinds(conn, inc.id)


def test_score_is_capped_at_100(conn):
    c = correlator()
    put(conn, detection(NOW, "SP-002"), detection(NOW, "SP-003"), detection(NOW, "SP-004"))
    c.run(conn, NOW)
    # 20 + 10 + 30 + 20 = 80 here; raise the weights via scoring to prove the cap
    from sentinelpi.config import IncidentSettings, ScoringSettings
    from sentinelpi.incidents.correlator import IncidentCorrelator

    heavy = IncidentCorrelator(
        IncidentSettings(), ScoringSettings(new_listening_port=90, watchlisted_process=90)
    )
    put(conn, detection(NOW + timedelta(minutes=1), "SP-002", host="b"))
    put(conn, detection(NOW + timedelta(minutes=1), "SP-004", host="b"))
    heavy.run(conn, NOW + timedelta(minutes=1))
    capped = [i for i in all_incidents(conn) if i.host == "b"]
    assert [i.risk_score for i in capped] == [100]


# ------------------------------------------------------------------ supporting rules
def test_cpu_alone_does_not_open_an_incident(conn):
    put(conn, detection(NOW, "SP-003"))
    report = correlator().run(conn, NOW)
    assert (report.created, report.unlinked) == (0, 1)
    assert all_incidents(conn) == []


def test_cpu_joins_an_existing_incident_even_when_it_is_older(conn):
    put(conn, detection(NOW - timedelta(minutes=10), "SP-003"), detection(NOW, "SP-002"))
    report = correlator().run(conn, NOW)  # same pass: openers are processed first
    assert (report.created, report.attached, report.unlinked) == (1, 1, 0)
    (inc,) = all_incidents(conn)
    assert inc.rule_ids == ["SP-002", "SP-003"] and inc.first_seen == NOW - timedelta(minutes=10)


def test_which_rules_may_open_incidents_is_configurable(conn):
    put(conn, detection(NOW, "SP-003"))
    correlator(open_incident_rules=["SP-003"]).run(conn, NOW)
    assert len(all_incidents(conn)) == 1


def test_config_rejects_unknown_rule_ids_and_typos():
    with pytest.raises(ValidationError):
        IncidentSettings(open_incident_rules=["SP-009"])
    with pytest.raises(ValidationError):
        IncidentSettings.model_validate({"correlation_window": 5})


# ------------------------------------------------------------------ incident state
def test_resolved_incidents_do_not_absorb_new_detections(conn):
    from sentinelpi.incidents.lifecycle import change_status

    put(conn, detection(NOW, ip=IP))
    c = correlator()
    c.run(conn, NOW)
    change_status(conn, all_incidents(conn)[0].id, IncidentStatus.RESOLVED, now=NOW)
    later = NOW + timedelta(minutes=5)
    put(conn, detection(later, ip=IP))
    c.run(conn, later)
    assert sorted(i.status.value for i in all_incidents(conn)) == ["open", "resolved"]


def test_acknowledged_incidents_still_receive_evidence_and_stay_acknowledged(conn):
    from sentinelpi.incidents.lifecycle import change_status

    put(conn, detection(NOW, ip=IP))
    c = correlator()
    c.run(conn, NOW)
    inc = all_incidents(conn)[0]
    change_status(conn, inc.id, IncidentStatus.ACKNOWLEDGED, now=NOW)
    later = NOW + timedelta(minutes=5)
    put(conn, detection(later, ip=IP))
    c.run(conn, later)
    (inc,) = all_incidents(conn)
    assert inc.status is IncidentStatus.ACKNOWLEDGED and inc.evidence_count == 2


# ------------------------------------------------------------------ robustness
def test_malformed_detections_are_skipped_without_blocking_others(conn):
    bad = detection(NOW, ip=IP, metadata={"rule_id": 7})
    unknown = detection(NOW, ip=IP, metadata={"rule_id": "SP-999"})
    good = detection(NOW, ip="203.0.113.50")
    put(conn, bad, unknown, good)
    report = correlator().run(conn, NOW)
    assert (report.skipped, report.created, report.errors) == (2, 1, 0)


def test_a_failure_on_one_detection_rolls_it_back_and_continues(conn, monkeypatch):
    first = detection(NOW, ip="203.0.113.1")
    second = detection(NOW + timedelta(seconds=1), ip="203.0.113.2")
    put(conn, first, second)
    real = incidents_repo.attach_event

    def flaky(c, incident_id, event_id):
        if str(event_id) == str(first.id):
            raise RuntimeError("boom")
        return real(c, incident_id, event_id)

    monkeypatch.setattr(incidents_repo, "attach_event", flaky)
    report = correlator().run(conn, NOW + timedelta(seconds=1))
    assert (report.errors, report.created) == (1, 1)
    (inc,) = all_incidents(conn)
    assert inc.source_ip == "203.0.113.2"  # nothing half-written for the failed one
    assert conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0] == 1
    # and the next pass retries it
    monkeypatch.setattr(incidents_repo, "attach_event", real)
    correlator().run(conn, NOW + timedelta(seconds=2))
    assert len(all_incidents(conn)) == 2


# ------------------------------------------------------------------ with the real engine
def test_real_ssh_detection_flows_into_an_incident(conn):
    put(conn, *burst(NOW - timedelta(seconds=60), 6, step_seconds=5, ip=IP))
    engine().run(conn, NOW)
    correlator().run(conn, NOW)
    (inc,) = all_incidents(conn)
    assert inc.source_ip == IP and inc.rule_ids == ["SP-001"]
    assert inc.evidence_count == 7  # the detection and the six attempts it names
    # a later evaluation that is suppressed by the cooldown adds nothing
    engine().run(conn, NOW + timedelta(minutes=1))
    correlator().run(conn, NOW + timedelta(minutes=1))
    assert incidents_repo.get_incident(conn, inc.id).evidence_count == 7


def test_unrelated_auth_events_are_never_attached(conn):
    stranger = auth_event(NOW, ip="198.51.100.4")
    put(conn, stranger, detection(NOW, ip=IP))
    correlator().run(conn, NOW)
    assert events_repo.get_event(conn, stranger.id) is not None
    assert incidents_repo.get_incident(conn, all_incidents(conn)[0].id).evidence_count == 1


# ------------------------------------------------------------------ retention interplay
def test_active_incident_evidence_survives_retention_until_resolved_and_expired(conn):
    from sentinelpi.incidents.lifecycle import change_status

    put(conn, detection(NOW, ip=IP))
    correlator().run(conn, NOW)
    inc = all_incidents(conn)[0]
    policy = RetentionSettings()

    far_future = NOW + timedelta(days=400)
    report = retention.run_retention(conn, policy, now=far_future)
    assert report.protected_old_events == 1
    assert events_repo.count_events(conn) == 1  # open incident: evidence is kept

    change_status(conn, inc.id, IncidentStatus.RESOLVED, now=far_future)
    retention.run_retention(conn, policy, now=far_future + timedelta(days=91))
    assert incidents_repo.get_incident(conn, inc.id) is None
    assert events_repo.count_events(conn) == 0  # released with the incident, then expired
    assert conn.execute("SELECT COUNT(*) FROM incident_audit").fetchone()[0] == 0
