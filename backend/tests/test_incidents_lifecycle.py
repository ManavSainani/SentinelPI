from datetime import timedelta

import pytest

from sentinelpi.events import Severity
from sentinelpi.incidents.lifecycle import (
    MAX_NOTE,
    IncidentNotFoundError,
    TransitionError,
    change_status,
)
from sentinelpi.incidents.models import IncidentStatus as S
from sentinelpi.storage import incidents_repo
from tests.conftest import NOW
from tests.helpers_incidents import correlator, detection, put


@pytest.fixture
def inc(conn):
    put(conn, detection(NOW, ip="203.0.113.9"))
    correlator().run(conn, NOW)
    return incidents_repo.list_incidents(conn)[0]


def history(conn, incident_id):
    return [
        (i.from_status, i.to_status, i.actor, i.note)
        for i in incidents_repo.get_timeline(conn, incident_id)
        if i.audit_kind == "status_changed"
    ]


def test_open_to_acknowledged_to_resolved_is_audited_with_notes(conn, inc):
    t1, t2 = NOW + timedelta(minutes=1), NOW + timedelta(minutes=9)
    a = change_status(conn, inc.id, S.ACKNOWLEDGED, now=t1)
    assert a.status is S.ACKNOWLEDGED and a.updated_at == t1 and a.resolution_note is None
    r = change_status(conn, inc.id, S.RESOLVED, note="blocked the address", now=t2)
    assert r.status is S.RESOLVED and r.resolution_note == "blocked the address"
    assert history(conn, inc.id) == [
        ("open", "acknowledged", "user", None),
        ("acknowledged", "resolved", "user", "blocked the address"),
    ]
    timeline = incidents_repo.get_timeline(conn, inc.id)
    changes = [i for i in timeline if i.audit_kind == "status_changed"]
    assert [c.at for c in changes] == [t1, t2]


@pytest.mark.parametrize(
    ("steps", "final"),
    [
        ([S.FALSE_POSITIVE], S.FALSE_POSITIVE),
        ([S.RESOLVED], S.RESOLVED),
        ([S.ACKNOWLEDGED, S.FALSE_POSITIVE], S.FALSE_POSITIVE),
    ],
)
def test_allowed_paths(conn, inc, steps, final):
    for step in steps:
        change_status(conn, inc.id, step, now=NOW)
    assert incidents_repo.get_incident(conn, inc.id).status is final


@pytest.mark.parametrize(
    ("setup", "target"),
    [
        ([], S.OPEN),
        ([S.ACKNOWLEDGED], S.ACKNOWLEDGED),
        ([S.ACKNOWLEDGED], S.OPEN),
        ([S.RESOLVED], S.ACKNOWLEDGED),
        ([S.RESOLVED], S.OPEN),
        ([S.RESOLVED], S.FALSE_POSITIVE),
        ([S.FALSE_POSITIVE], S.RESOLVED),
    ],
)
def test_invalid_transitions_are_refused_and_change_nothing(conn, inc, setup, target):
    for step in setup:
        change_status(conn, inc.id, step, now=NOW)
    before = incidents_repo.get_incident(conn, inc.id)
    audit_before = history(conn, inc.id)
    with pytest.raises(TransitionError):
        change_status(conn, inc.id, target, note="nope", now=NOW + timedelta(hours=1))
    assert incidents_repo.get_incident(conn, inc.id) == before
    assert history(conn, inc.id) == audit_before


def test_unknown_incident(conn):
    with pytest.raises(IncidentNotFoundError):
        change_status(conn, "does-not-exist", S.RESOLVED)


def test_notes_are_cleaned_redacted_and_bounded(conn, inc):
    change_status(conn, inc.id, S.RESOLVED, note="fixed\nline2 password=hunter2 " + "x" * 900)
    note = incidents_repo.get_incident(conn, inc.id).resolution_note
    assert "\n" not in note and "hunter2" not in note and len(note) <= MAX_NOTE


def test_a_concurrent_change_is_detected_and_not_audited(conn, inc, monkeypatch):
    monkeypatch.setattr(incidents_repo, "set_status", lambda *a, **k: False)
    with pytest.raises(TransitionError):
        change_status(conn, inc.id, S.RESOLVED, now=NOW)
    assert history(conn, inc.id) == []


def test_a_status_change_never_alters_evidence_or_derived_fields(conn, inc):
    before = incidents_repo.get_incident(conn, inc.id)
    change_status(conn, inc.id, S.ACKNOWLEDGED, now=NOW)
    after = incidents_repo.get_incident(conn, inc.id)
    derived = ("severity", "risk_score", "rule_ids", "first_seen", "last_seen", "evidence_count")
    for field in derived:
        assert getattr(after, field) == getattr(before, field)
    assert after.severity is Severity.HIGH


# ------------------------------------------------------------------ repository queries
def test_prefix_lookup(conn, inc):
    assert incidents_repo.resolve_id(conn, inc.id[:8]) == inc.id
    assert incidents_repo.resolve_id(conn, inc.id.upper()) == inc.id
    assert incidents_repo.resolve_id(conn, "ffffffff") is None
    for hostile in ("", "%", "_", "' OR 1=1 --", "zz"):
        assert incidents_repo.resolve_id(conn, hostile) is None


def test_ambiguous_prefix_is_refused(conn, inc):
    for new_id in ("aaaa1111-0000", "aaaa2222-0000"):
        incidents_repo.create_incident(conn, inc.model_copy(update={"id": new_id}))
    with pytest.raises(incidents_repo.AmbiguousIdError):
        incidents_repo.resolve_id(conn, "aaaa")
    assert incidents_repo.resolve_id(conn, "aaaa1") == "aaaa1111-0000"


def test_listing_filters_and_is_bounded(conn):
    for i in range(3):
        t = NOW + timedelta(minutes=i)
        put(conn, detection(t, ip=f"203.0.113.{i + 1}"))
        correlator().run(conn, t)
    put(conn, detection(NOW, "SP-002", severity=Severity.MEDIUM))
    correlator().run(conn, NOW)
    items = incidents_repo.list_incidents(conn)
    assert len(items) == 4 and items == sorted(items, key=lambda i: i.last_seen, reverse=True)
    assert len(incidents_repo.list_incidents(conn, limit=0)) == 1  # clamped to at least 1
    assert len(incidents_repo.list_incidents(conn, min_severity=Severity.HIGH)) == 3
    change_status(conn, items[0].id, S.RESOLVED, now=NOW)
    assert len(incidents_repo.list_incidents(conn, status=S.RESOLVED)) == 1
    assert incidents_repo.count_by_status(conn) == {
        "open": 3,
        "acknowledged": 0,
        "resolved": 1,
        "false_positive": 0,
    }


def test_timeline_is_chronological_and_bounded(conn, inc):
    change_status(conn, inc.id, S.ACKNOWLEDGED, now=NOW + timedelta(minutes=2))
    items = incidents_repo.get_timeline(conn, inc.id)
    assert [i.at for i in items] == sorted(i.at for i in items)
    assert items[0].kind == "event" and items[0].event_type == "detection.ssh_repeated_failures"
    assert items[-1].audit_kind == "status_changed"
    # the limit applies to each kind separately: one evidence row plus one audit row
    assert len(incidents_repo.get_timeline(conn, inc.id, limit=1)) == 2
