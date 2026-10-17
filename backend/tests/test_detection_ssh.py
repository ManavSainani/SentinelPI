from datetime import timedelta

import pytest

from sentinelpi.config import ScoringSettings
from sentinelpi.config import SshFailuresRule as Cfg
from sentinelpi.detection.rules.ssh_failures import MAX_EVIDENCE, SshFailuresRule, evidence_ids
from sentinelpi.events import EventSource, Severity
from sentinelpi.storage import events_repo
from tests.conftest import NOW
from tests.helpers_detection import FAILED, INVALID, SUCCESS, auth_event, burst

SCORING = ScoringSettings()


def rule(**kw):
    return SshFailuresRule(Cfg(**kw), SCORING)


def run(conn, events, r=None, now=NOW):
    events_repo.insert_events(conn, events)
    return (r or rule()).evaluate(conn, now)


def test_positive_five_failures_in_two_minutes(conn):
    evs = burst(NOW - timedelta(seconds=120), 5, step_seconds=30)
    res = run(conn, evs)
    assert res.skipped_reason is None and len(res.detections) == 1
    d = res.detections[0]
    e = d.event
    assert d.rule_id == "SP-001" and d.dedupe_key == "SP-001:203.0.113.9"
    assert e.severity == Severity.HIGH and e.source == EventSource.AUTH_LOG
    assert e.event_type == "detection.ssh_repeated_failures" and e.source_ip == "203.0.113.9"
    assert e.metadata["attempts"] == 5 and e.metadata["risk_points"] == 35
    assert "at least 5 failed SSH attempts" in e.metadata["trigger"]
    assert e.metadata["rule_id"] == "SP-001" and e.metadata["dedupe_key"] == d.dedupe_key
    assert set(map(str, evidence_ids(e))) == {str(x.id) for x in evs}
    assert e.summary.startswith("SP-001: 5 failed SSH attempts from 203.0.113.9")


def test_negative_four_failures(conn):
    assert run(conn, burst(NOW - timedelta(seconds=100), 4)).detections == []


def test_boundary_window_is_inclusive(conn):
    # five attempts spanning exactly 5 minutes still count...
    exact = burst(NOW - timedelta(seconds=300), 5, step_seconds=75)
    assert len(run(conn, exact).detections) == 1


def test_boundary_one_second_over_does_not_trigger(conn):
    over = burst(NOW - timedelta(seconds=301), 5, step_seconds=75.25)
    assert run(conn, over).detections == []


def test_attempts_spread_across_windows_do_not_trigger(conn):
    # 6 attempts, one every 150 s: no 5-minute window holds more than 3.
    assert run(conn, burst(NOW - timedelta(seconds=750), 6, step_seconds=150)).detections == []


def test_failures_from_different_ips_are_not_pooled(conn):
    evs = burst(NOW - timedelta(seconds=60), 3, ip="203.0.113.1") + burst(
        NOW - timedelta(seconds=60), 3, ip="203.0.113.2"
    )
    assert run(conn, evs).detections == []


def test_two_offending_ips_give_two_detections(conn):
    evs = burst(NOW - timedelta(seconds=60), 5, ip="203.0.113.2") + burst(
        NOW - timedelta(seconds=60), 6, ip="203.0.113.1"
    )
    keys = [d.dedupe_key for d in run(conn, evs).detections]
    assert keys == ["SP-001:203.0.113.1", "SP-001:203.0.113.2"]


def test_burst_that_ended_before_this_evaluation_is_still_seen(conn):
    ended = burst(NOW - timedelta(minutes=9), 5, step_seconds=20)  # within 2 windows
    assert len(run(conn, ended).detections) == 1


def test_burst_older_than_the_lookback_is_ignored(conn):
    assert run(conn, burst(NOW - timedelta(minutes=12), 5, step_seconds=20)).detections == []


def test_future_dated_events_are_ignored(conn):
    assert run(conn, burst(NOW + timedelta(minutes=1), 5)).detections == []


def test_only_real_auth_log_events_count(conn):
    fake = burst(NOW - timedelta(seconds=60), 8, source=EventSource.TEST)
    assert run(conn, fake).detections == []


def test_detection_events_are_not_counted_as_attempts(conn):
    own = [
        auth_event(NOW - timedelta(seconds=i), "detection.ssh_repeated_failures", port=1000 + i)
        for i in range(10)
    ]
    assert run(conn, own).detections == []


def test_invalid_user_and_failed_login_of_one_connection_count_once(conn):
    t = NOW - timedelta(seconds=120)
    evs = []
    for i in range(4):  # 4 connections, each logs invalid-user + failed login
        ts = t + timedelta(seconds=i * 20)
        evs += [auth_event(ts, INVALID, port=5000 + i), auth_event(ts, FAILED, port=5000 + i)]
    assert run(conn, evs).detections == []  # 4 real attempts, not 8
    evs5 = [
        auth_event(t + timedelta(seconds=100), INVALID, port=5009),
        auth_event(t + timedelta(seconds=100), FAILED, port=5009),
    ]
    res = run(conn, evs5)
    assert len(res.detections) == 1 and res.detections[0].event.metadata["attempts"] == 5


def test_several_password_tries_on_one_connection_each_count(conn):
    # real Pi data: one invalid-user event, then one failed login per password typed.
    t = NOW - timedelta(seconds=60)
    evs = [auth_event(t, INVALID, port=52998)] + [
        auth_event(t + timedelta(seconds=5 * i), FAILED, port=52998) for i in range(1, 6)
    ]
    res = run(conn, evs)
    assert res.detections[0].event.metadata["attempts"] == 5


def test_invalid_user_only_when_password_login_is_disabled(conn):
    res = run(
        conn, [auth_event(NOW - timedelta(seconds=i), INVALID, port=6000 + i) for i in range(5)]
    )
    assert len(res.detections) == 1


def test_legacy_invalid_user_without_port_is_matched_by_time(conn):
    t = NOW - timedelta(seconds=60)
    evs = []
    for i in range(4):
        ts = t + timedelta(seconds=i * 10)
        evs += [
            auth_event(ts, INVALID),
            auth_event(ts + timedelta(seconds=1), FAILED, port=7000 + i),
        ]
    assert run(conn, evs).detections == []  # 4 attempts; the portless lines are the same ones


def test_ignored_source_ip(conn):
    evs = burst(NOW - timedelta(seconds=60), 9, ip="198.51.100.7")
    assert run(conn, evs, rule(ignored_source_ips=["198.51.100.7"])).detections == []


def test_login_after_failures_is_flagged(conn):
    evs = burst(NOW - timedelta(seconds=100), 5) + [
        auth_event(NOW - timedelta(seconds=5), SUCCESS, user="pi", user_exists=True)
    ]
    e = run(conn, evs).detections[0].event
    assert e.metadata["login_after_failures"] is True and "successful login" in e.summary


def test_login_from_another_ip_is_not_flagged(conn):
    evs = burst(NOW - timedelta(seconds=100), 5) + [
        auth_event(NOW - timedelta(seconds=5), SUCCESS, ip="192.168.1.5", user="pi")
    ]
    assert run(conn, evs).detections[0].event.metadata["login_after_failures"] is False


def test_unknown_users_and_targeted_accounts_are_summarized(conn):
    evs = burst(NOW - timedelta(seconds=100), 4, user=None, user_exists=False) + [
        auth_event(NOW - timedelta(seconds=10), FAILED, port=1, user="root", user_exists=True)
    ]
    m = run(conn, evs).detections[0].event.metadata
    assert m["unknown_user_attempts"] == 4 and m["targeted_accounts"] == ["root"]


def test_evidence_list_is_bounded(conn):
    big = burst(NOW - timedelta(seconds=250), 60, step_seconds=4)
    m = run(conn, big).detections[0].event.metadata
    assert m["attempts"] == 60 and len(m["evidence_event_ids"]) == MAX_EVIDENCE
    assert m["evidence_truncated"] is True


def test_threshold_is_configurable(conn):
    events_repo.insert_events(conn, burst(NOW - timedelta(seconds=100), 3))
    assert rule(threshold=3).evaluate(conn, NOW).detections
    assert not rule(threshold=4).evaluate(conn, NOW).detections


def test_window_is_configurable(conn):
    # three attempts 4 minutes apart span 8 minutes: too wide for 5, fine for 10.
    events_repo.insert_events(conn, burst(NOW - timedelta(minutes=8), 3, step_seconds=240))
    assert not rule(threshold=3, window_minutes=5).evaluate(conn, NOW).detections
    assert rule(threshold=3, window_minutes=10).evaluate(conn, NOW).detections


@pytest.mark.parametrize("bad", [{"threshold": 1}, {"window_minutes": 0}, {"cooldown_minutes": 0}])
def test_invalid_config_rejected(bad):
    with pytest.raises(ValueError):
        Cfg(**bad)
