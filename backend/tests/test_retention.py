import os
from datetime import timedelta

from sentinelpi.config import RetentionSettings
from sentinelpi.events import Event, EventSource, Severity
from sentinelpi.storage import events_repo, telemetry_repo
from sentinelpi.storage.retention import db_used_bytes, run_retention
from sentinelpi.synthetic import generate_metrics
from sentinelpi.timeutil import to_db
from tests.conftest import NOW
from tests.test_telemetry_repo import proc_snap

POLICY = RetentionSettings(events_days=14, metrics_days=7, snapshot_days=3, incident_days=90)


def days_ago(n):
    return NOW - timedelta(days=n)


def event(age_days, label="e", **kw):
    return Event(
        timestamp=days_ago(age_days),
        source=EventSource.TEST,
        event_type="test.event",
        severity=Severity.LOW,
        summary=f"{label} {age_days}d",
        host="pi",
        **kw,
    )


def incident(conn, iid, status, updated_days_ago):
    ts = to_db(days_ago(updated_days_ago))
    conn.execute(
        "INSERT INTO incidents"
        " (id,title,severity,status,first_seen,last_seen,created_at,updated_at)"
        " VALUES (?,?,?,?,?,?,?,?)",
        (iid, "t", "high", status, ts, ts, ts, ts),
    )


def link(conn, iid, ev, via_column=True, via_table=False):
    if via_column:
        conn.execute("UPDATE events SET incident_id = ? WHERE id = ?", (iid, str(ev.id)))
    if via_table:
        conn.execute("INSERT INTO incident_events VALUES (?, ?)", (iid, str(ev.id)))


def ids(conn):
    return {r[0] for r in conn.execute("SELECT id FROM events")}


def test_age_based_pruning_per_table(conn):
    telemetry_repo.insert_metrics_many(conn, generate_metrics(1, start=days_ago(8)))
    telemetry_repo.insert_metrics_many(conn, generate_metrics(1, start=days_ago(6)))
    telemetry_repo.insert_process_snapshot(conn, proc_snap(days_ago(4), [1]))
    telemetry_repo.insert_process_snapshot(conn, proc_snap(days_ago(2), [2]))
    old, fresh = event(15), event(13)
    events_repo.insert_events(conn, [old, fresh])

    report = run_retention(conn, POLICY, now=NOW)

    assert report.deleted["system_metrics"] == 1 and report.deleted["process_snapshots"] == 1
    assert report.deleted["events"] == 1
    assert ids(conn) == {str(fresh.id)}
    assert conn.execute("SELECT COUNT(*) FROM system_metrics").fetchone()[0] == 1
    assert telemetry_repo.latest_process_snapshot(conn)[1][0].pid == 2


def test_second_run_is_a_no_op(conn):
    events_repo.insert_event(conn, event(30))
    run_retention(conn, POLICY, now=NOW)
    again = run_retention(conn, POLICY, now=NOW)
    assert sum(again.deleted.values()) == 0


def test_evidence_of_unresolved_incidents_is_never_deleted(conn):
    a, b, c = event(200, "col"), event(200, "table"), event(200, "ack")
    events_repo.insert_events(conn, [a, b, c])
    incident(conn, "open1", "open", 400)  # ancient but unresolved
    incident(conn, "ack1", "acknowledged", 400)
    link(conn, "open1", a)  # via events.incident_id
    link(conn, "open1", b, via_column=False, via_table=True)  # via incident_events
    link(conn, "ack1", c)

    report = run_retention(conn, POLICY, now=NOW)

    assert ids(conn) == {str(a.id), str(b.id), str(c.id)}
    assert report.protected_old_events == 3
    assert conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0] == 2


def test_resolved_incident_keeps_evidence_until_it_expires(conn):
    ev = event(60)  # far past the 14-day event window
    events_repo.insert_event(conn, ev)
    incident(conn, "r1", "resolved", 30)  # resolved 30d ago; incident_days is 90
    link(conn, "r1", ev)

    run_retention(conn, POLICY, now=NOW)
    assert str(ev.id) in ids(conn)  # incident still retained => evidence retained

    conn.execute("UPDATE incidents SET updated_at = ? WHERE id = 'r1'", (to_db(days_ago(91)),))
    report = run_retention(conn, POLICY, now=NOW)
    assert report.deleted["incidents"] == 1
    assert str(ev.id) not in ids(conn)  # incident expired => evidence released and pruned


def test_false_positive_expires_but_open_never_does(conn):
    incident(conn, "fp", "false_positive", 120)
    incident(conn, "op", "open", 500)
    run_retention(conn, POLICY, now=NOW)
    remaining = {r[0] for r in conn.execute("SELECT id FROM incidents")}
    assert remaining == {"op"}


def test_size_target_trims_oldest_high_volume_data_and_shrinks_file(db):
    with db.session() as conn:
        telemetry_repo.insert_metrics_many(conn, generate_metrics(30000, start=days_ago(5)))
        protected = event(100)
        keep_fresh = event(1)
        events_repo.insert_events(conn, [protected, keep_fresh])
        incident(conn, "o", "open", 1)
        link(conn, "o", protected)
    size_before = os.path.getsize(db.path)

    with db.session() as conn:
        used_before = db_used_bytes(conn)
        report = run_retention(conn, POLICY, now=NOW, max_db_bytes=used_before // 3)
        assert report.size_target_met
        assert report.size_cap_deleted["system_metrics"] > 0
        assert report.used_bytes_after <= used_before // 3
        assert {str(protected.id), str(keep_fresh.id)} <= ids(conn)  # events untouched
        # Oldest were trimmed first: the newest metric survives.
        newest = generate_metrics(30000, start=days_ago(5))[-1].timestamp
        assert telemetry_repo.latest_metrics(conn).timestamp == newest
    assert os.path.getsize(db.path) < size_before  # file really shrank


def test_size_target_never_deletes_protected_evidence(conn):
    big = {f"k{i}": "x" * 200 for i in range(15)}  # ~3 KB metadata per event
    evs = [event(100, f"p{i}", metadata=big) for i in range(150)]
    events_repo.insert_events(conn, evs)
    incident(conn, "o", "open", 1)
    for e in evs:
        link(conn, "o", e)

    report = run_retention(conn, POLICY, now=NOW, max_db_bytes=50_000)

    assert report.size_target_met is False  # reported, not "fixed" by deleting evidence
    assert len(ids(conn)) == 150
    assert "events" not in report.size_cap_deleted


def test_size_target_can_trim_unprotected_events_last(conn):
    big = {f"k{i}": "x" * 200 for i in range(15)}
    events_repo.insert_events(conn, [event(1, f"u{i}", metadata=big) for i in range(150)])
    # An empty schema alone is ~112 KB, so the target must be reachable to be meaningful.
    report = run_retention(conn, POLICY, now=NOW, max_db_bytes=300_000)
    trimmed = report.size_cap_deleted.get("events", 0)
    assert 0 < trimmed < 150  # trimmed enough to hit the target, not everything
    assert report.size_target_met
    assert len(ids(conn)) == 150 - trimmed
