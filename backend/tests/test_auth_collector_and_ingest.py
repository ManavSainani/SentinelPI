import json
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from sentinelpi.collectors.auth_logs import AuthLogCollector, build_auth_collector
from sentinelpi.collectors.auth_parser import RawAuthEntry
from sentinelpi.collectors.auth_sources import JournalSource, SourceRead
from sentinelpi.collectors.base import CollectorState
from sentinelpi.config import AuthSettings
from sentinelpi.storage import events_repo, state_repo
from sentinelpi.storage.auth_ingest import poll_auth_logs
from tests.test_auth_sources import FakeProc, jline

NOW = datetime(2026, 9, 28, 19, 30, tzinfo=UTC)
KNOWN = {"msainani", "root"}


def entry(msg, eid, source="journal"):
    return RawAuthEntry(eid, NOW, "manavpi", msg, source)


class Stub:
    def __init__(self, name, read):
        self.name, self._read, self.calls = name, read, []

    def read(self, cursor, now):
        self.calls.append(cursor)
        return self._read


def collector(*sources):
    return AuthLogCollector(list(sources), user_exists=lambda n: n in KNOWN)


FAILED = "Failed password for root from 203.0.113.5 port 22 ssh2"


def test_events_ignored_and_malformed_are_counted():
    read = SourceRead(
        CollectorState.OK,
        entries=[
            entry(FAILED, "1"),
            entry("Server listening on :: port 22.", "2"),
            entry("Failed password for root from bogus port 22 ssh2", "3"),
        ],
        next_cursor="3",
    )
    poll = collector(Stub("journal", read)).poll({}, NOW)
    batch = poll.result.data
    assert poll.result.status.state == CollectorState.OK
    assert (len(batch.events), batch.ignored, batch.malformed, batch.entries_read) == (1, 1, 1, 3)
    assert poll.cursors == {"journal": "3"}
    assert "1 malformed" in poll.result.status.detail


def test_falls_through_unavailable_sources_and_says_why():
    denied = Stub("journal", SourceRead(CollectorState.UNAVAILABLE, "no permission"))
    ok = Stub(
        "auth_log",
        SourceRead(
            CollectorState.OK, entries=[entry(FAILED, "9", "auth_log")], next_cursor="1:5:ab"
        ),
    )
    poll = collector(denied, ok).poll({"auth_log": "old"}, NOW)
    status = poll.result.status
    assert status.state == CollectorState.DEGRADED and poll.result.data.source == "auth_log"
    assert "journal: no permission" in status.detail
    assert ok.calls == ["old"] and poll.cursors == {"auth_log": "1:5:ab"}


def test_error_source_also_falls_through():
    bad = Stub("journal", SourceRead(CollectorState.ERROR, "exit 2"))
    ok = Stub("auth_log", SourceRead(CollectorState.OK))
    assert collector(bad, ok).poll({}, NOW).result.data.source == "auth_log"


def test_first_healthy_source_wins_and_later_ones_are_not_read():
    first = Stub("journal", SourceRead(CollectorState.OK, next_cursor="c1"))
    second = Stub("auth_log", SourceRead(CollectorState.OK))
    poll = collector(first, second).poll({}, NOW)
    assert poll.result.status.state == CollectorState.OK and second.calls == []


def test_everything_unavailable_is_reported_without_data():
    a = Stub("journal", SourceRead(CollectorState.UNAVAILABLE, "no journalctl"))
    b = Stub("auth_log", SourceRead(CollectorState.UNAVAILABLE, "no file"))
    poll = collector(a, b).poll({"journal": "keep"}, NOW)
    assert poll.result.data is None and poll.result.status.state == CollectorState.UNAVAILABLE
    assert "no journalctl" in poll.result.status.detail and "no file" in poll.result.status.detail
    assert poll.cursors == {"journal": "keep"}


# ---------------------------------------------------------------- storage integration
def stub_collector(entries, cursor="c-last"):
    read = SourceRead(CollectorState.OK, entries=entries, next_cursor=cursor)
    return collector(Stub("journal", read))


def test_events_and_cursor_are_stored_together(db):
    c = stub_collector(
        [entry(FAILED, "1"), entry("Accepted password for msainani from 10.0.0.2 port 5 ssh2", "2")]
    )
    with db.session() as conn:
        report = poll_auth_logs(conn, c, NOW)
    assert (report.events_parsed, report.events_stored) == (2, 2)
    with db.session() as conn:
        assert events_repo.count_events(conn) == 2
        assert state_repo.get_state(conn, "auth.cursor.journal") == "c-last"


def test_rereading_the_same_entries_never_duplicates(db):
    c = stub_collector([entry(FAILED, "1")])
    with db.session() as conn:
        poll_auth_logs(conn, c, NOW)
    with db.session() as conn:  # e.g. cursor lost after a crash
        conn.execute("DELETE FROM collector_state")
        again = poll_auth_logs(conn, c, NOW)
        assert (again.events_parsed, again.events_stored) == (1, 0)
        assert events_repo.count_events(conn) == 1


def test_saved_cursor_is_passed_back_to_the_source(db):
    stub = Stub("journal", SourceRead(CollectorState.OK, next_cursor="c2"))
    c = collector(stub)
    with db.session() as conn:
        state_repo.set_state(conn, "auth.cursor.journal", "c1")
        poll_auth_logs(conn, c, NOW)
    assert stub.calls == ["c1"]


def test_nothing_is_saved_if_the_transaction_fails(db):
    c = stub_collector([entry(FAILED, "1")])
    with pytest.raises(RuntimeError), db.session() as conn:
        poll_auth_logs(conn, c, NOW)
        raise RuntimeError("crash before commit")
    with db.session() as conn:
        assert events_repo.count_events(conn) == 0
        assert state_repo.get_state(conn, "auth.cursor.journal") is None


def test_unavailable_source_leaves_cursor_untouched(db):
    c = collector(Stub("journal", SourceRead(CollectorState.UNAVAILABLE, "denied")))
    with db.session() as conn:
        state_repo.set_state(conn, "auth.cursor.journal", "keep")
        report = poll_auth_logs(conn, c, NOW)
        assert report.state == CollectorState.UNAVAILABLE and report.source is None
        assert state_repo.get_state(conn, "auth.cursor.journal") == "keep"


def test_end_to_end_journal_to_database_stores_no_credentials(db):
    lines = [
        jline("c1", "Failed password for invalid user hunter2 from 203.0.113.5 port 4001 ssh2"),
        jline("c2", "Failed password for root from 203.0.113.5 port 4002 ssh2"),
        jline(
            "c3",
            "Accepted publickey for msainani from 192.168.1.20 port 5 ssh2: "
            "ED25519 SHA256:secretfp",
        ),
        jline(
            "c4", "Failed password for root from 6.6.6.6 port 1 ssh2", unit="session-9.scope"
        ),  # forged
        jline("c5", "Server listening on 0.0.0.0 port 22."),
    ]
    src = JournalSource(
        ["ssh.service"], popen=lambda *a, **k: FakeProc(lines), which=lambda _: "/x"
    )
    c = AuthLogCollector([src], user_exists=lambda n: n in KNOWN)
    with db.session() as conn:
        report = poll_auth_logs(conn, c, NOW)
        assert report.state == CollectorState.OK and report.events_stored == 3
        rows = [dict(r) for r in conn.execute("SELECT * FROM events ORDER BY timestamp, id")]
        everything = json.dumps(rows)
        assert "hunter2" not in everything and "secretfp" not in everything
        assert "6.6.6.6" not in everything  # forged line rejected
        assert {r["source"] for r in rows} == {"auth_log"}
        assert state_repo.get_state(conn, "auth.cursor.journal") == "c5"


# ---------------------------------------------------------------- config / state
def test_build_collector_prefers_journal_then_file():
    assert build_auth_collector(AuthSettings()).source_names == ["journal", "auth_log"]


@pytest.mark.parametrize("bad", [["--evil"], ["ssh"], [], ["ok.service", "x; rm.service"]])
def test_config_rejects_bad_unit_names(bad):
    with pytest.raises(ValidationError):
        AuthSettings(journal_units=bad)


def test_state_repo_upserts_and_validates(conn):
    state_repo.set_state(conn, "k.1", "a")
    state_repo.set_state(conn, "k.1", "b")
    assert state_repo.get_state(conn, "k.1") == "b" and state_repo.get_state(conn, "nope") is None
    with pytest.raises(ValueError):
        state_repo.set_state(conn, "bad key", "x")
    with pytest.raises(ValueError):
        state_repo.set_state(conn, "k", "x" * 2000)
