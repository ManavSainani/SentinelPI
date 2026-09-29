import sqlite3
from datetime import timedelta

import pytest

from sentinelpi.events import Event, EventSource, Severity
from sentinelpi.storage import events_repo as repo
from sentinelpi.synthetic import generate_events
from tests.conftest import NOW


def make(i=0, **over):
    base = {
        "timestamp": NOW + timedelta(seconds=i),
        "source": EventSource.AUTH_LOG,
        "event_type": "auth.ssh_failed_login",
        "severity": Severity.LOW,
        "summary": f"event {i}",
        "host": "pi",
    }
    base.update(over)
    return Event(**base)


def test_roundtrip_preserves_everything(conn):
    e = make(source_ip="2001:db8::1", username="root", process_name="sshd", metadata={"n": [1, 2]})
    repo.insert_event(conn, e)
    assert repo.get_event(conn, e.id) == e
    assert repo.get_event(conn, str(e.id)) == e


def test_get_missing_returns_none(conn):
    assert repo.get_event(conn, "00000000-0000-0000-0000-000000000000") is None


def test_duplicate_id_rejected(conn):
    e = make()
    repo.insert_event(conn, e)
    with pytest.raises(sqlite3.IntegrityError):
        repo.insert_event(conn, e)


def test_list_is_newest_first_and_counts(conn):
    repo.insert_events(conn, [make(i) for i in range(5)])
    assert [e.summary for e in repo.list_events(conn)] == [f"event {i}" for i in (4, 3, 2, 1, 0)]
    assert repo.count_events(conn) == 5


def test_time_window_is_inclusive_start_exclusive_end(conn):
    repo.insert_events(conn, [make(i) for i in range(5)])
    got = repo.list_events(conn, since=NOW + timedelta(seconds=1), until=NOW + timedelta(seconds=3))
    assert sorted(e.summary for e in got) == ["event 1", "event 2"]


def test_filters(conn):
    repo.insert_events(
        conn,
        [
            make(0, severity=Severity.INFO),
            make(1, severity=Severity.HIGH, source_ip="203.0.113.7"),
            make(2, severity=Severity.CRITICAL, event_type="process.watchlist_match"),
            make(3, source=EventSource.TEST),
        ],
    )
    assert len(repo.list_events(conn, min_severity=Severity.HIGH)) == 2
    assert len(repo.list_events(conn, source=EventSource.TEST)) == 1
    assert len(repo.list_events(conn, event_type="process.watchlist_match")) == 1
    assert len(repo.list_events(conn, source_ip="203.0.113.7")) == 1


def test_limit_is_always_bounded(conn):
    repo.insert_events(conn, generate_events(600, start=NOW))
    assert len(repo.list_events(conn, limit=10**9)) == repo.MAX_LIMIT
    assert len(repo.list_events(conn, limit=0)) == 1


def test_filter_values_cannot_inject_sql(conn):
    repo.insert_event(conn, make())
    assert repo.list_events(conn, event_type="x' OR '1'='1") == []
    assert repo.list_events(conn, source_ip="1.1.1.1'; DROP TABLE events;--") == []
    assert repo.count_events(conn) == 1


def test_session_rolls_back_on_error(db):
    with pytest.raises(RuntimeError), db.session() as c:
        repo.insert_event(c, make())
        raise RuntimeError("boom")
    with db.session() as c:
        assert repo.count_events(c) == 0


def test_corrupted_metadata_does_not_break_listing(conn):
    e = make(metadata={"a": 1})
    repo.insert_event(conn, e)
    conn.execute("UPDATE events SET metadata_json = '{not json'")
    assert repo.get_event(conn, e.id).metadata == {}
