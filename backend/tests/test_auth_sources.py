import io
import json
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from sentinelpi.collectors.auth_sources import (
    AuthLogFileSource,
    JournalSource,
    parse_syslog_line,
)
from sentinelpi.collectors.base import CollectorState

NOW = datetime(2026, 9, 28, 19, 30, 0, tzinfo=UTC)
EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
MSG = "Failed password for root from 203.0.113.5 port 22 ssh2"


def micros(dt):
    return str(int((dt - EPOCH).total_seconds() * 1_000_000))


def jline(cursor, msg=MSG, unit="ssh.service", ts=NOW, host="manavpi", **extra):
    obj = {
        "__CURSOR": cursor,
        "__REALTIME_TIMESTAMP": micros(ts),
        "MESSAGE": msg,
        "_SYSTEMD_UNIT": unit,
        "_HOSTNAME": host,
    }
    obj.update(extra)
    return json.dumps(obj) + "\n"


class FakeProc:
    def __init__(self, lines, stderr="", returncode=0):
        self.stdout = iter(lines)
        self.stderr = io.StringIO(stderr)
        self.returncode = returncode
        self.killed = False

    def kill(self):
        self.killed = True
        self.returncode = -9

    def wait(self):
        return self.returncode


def journal(procs, **kw):
    calls = []
    queue = list(procs)

    def popen(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return queue.pop(0)

    src = JournalSource(
        ["ssh.service", "sshd.service"], popen=popen, which=lambda _: "/usr/bin/journalctl", **kw
    )
    return src, calls


# ---------------------------------------------------------------- journal
def test_command_is_a_safe_argument_list_with_lookback_on_first_run():
    src, calls = journal([FakeProc([])], lookback_minutes=15)
    src.read(None, NOW)
    cmd, kwargs = calls[0]
    assert isinstance(cmd, list) and not kwargs.get("shell")
    assert cmd[0] == "journalctl" and "--unit=ssh.service" in cmd and "--unit=sshd.service" in cmd
    assert "--since=2026-09-28 19:15:00 UTC" in cmd
    assert kwargs["env"]["LC_ALL"] == "C"


def test_resumes_from_cursor_and_rejects_hostile_cursor():
    src, calls = journal([FakeProc([]), FakeProc([])])
    src.read("s=abc;i=1;b=2;m=3;t=4;x=5", NOW)
    src.read("x; rm -rf /", NOW)
    assert "--after-cursor=s=abc;i=1;b=2;m=3;t=4;x=5" in calls[0][0]
    assert not any(a.startswith("--after-cursor") for a in calls[1][0])
    assert any(a.startswith("--since=") for a in calls[1][0])


def test_reads_entries_with_utc_timestamps_and_advances_cursor():
    ts = NOW - timedelta(seconds=5)
    src, _ = journal([FakeProc([jline("c1", ts=ts), jline("c2", ts=NOW)])])
    r = src.read(None, NOW)
    assert r.state == CollectorState.OK and r.next_cursor == "c2"
    assert [e.entry_id for e in r.entries] == ["c1", "c2"]
    assert r.entries[0].timestamp == ts and r.entries[0].host == "manavpi"
    assert r.entries[0].source_name == "journal"


def test_forged_sshd_lines_from_other_units_are_rejected():
    # `logger -t sshd "Failed password ..."` from a user session lands in a session scope.
    lines = [jline("c1", unit="session-3.scope"), jline("c2", unit="init.scope"), jline("c3")]
    r = journal([FakeProc(lines)])[0].read(None, NOW)
    assert [e.entry_id for e in r.entries] == ["c3"]
    assert r.ignored == 2 and r.next_cursor == "c3"


def test_binary_message_arrays_are_decoded():
    line = jline("c1", msg=list(MSG.encode()))
    assert journal([FakeProc([line])])[0].read(None, NOW).entries[0].message == MSG


def test_malformed_lines_are_counted_not_fatal():
    lines = [
        "{not json\n",
        "[1,2]\n",
        json.dumps({"MESSAGE": "no cursor"}) + "\n",
        "-- No entries --\n",
        "\n",
        jline("c1"),
    ]
    r = journal([FakeProc(lines)])[0].read(None, NOW)
    assert r.malformed == 3 and len(r.entries) == 1 and r.state == CollectorState.OK


def test_permission_denied_is_reported_with_the_fix():
    err = "Hint: You are currently not seeing messages from other users and the system.\n"
    r = journal([FakeProc([], stderr=err)])[0].read(None, NOW)
    assert r.state == CollectorState.UNAVAILABLE and "systemd-journal" in r.detail


def test_missing_journalctl_is_unavailable():
    src = JournalSource(["ssh.service"], which=lambda _: None)
    assert src.read(None, NOW).state == CollectorState.UNAVAILABLE

    def boom(*a, **k):
        raise FileNotFoundError

    src = JournalSource(["ssh.service"], popen=boom, which=lambda _: "/x")
    assert src.read(None, NOW).state == CollectorState.UNAVAILABLE


def test_unexpected_exit_status_is_an_error():
    r = journal([FakeProc([], stderr="boom", returncode=2)])[0].read(None, NOW)
    assert r.state == CollectorState.ERROR and "2" in r.detail


def test_stale_cursor_falls_back_to_lookback_once():
    bad = FakeProc([], stderr="Failed to seek to cursor: No such file\n", returncode=1)
    good = FakeProc([jline("c9")])
    src, calls = journal([bad, good])
    r = src.read("s=old", NOW)
    assert r.state == CollectorState.DEGRADED and r.next_cursor == "c9"
    assert any(a.startswith("--since=") for a in calls[1][0])


def test_max_entries_caps_a_flood_and_keeps_position():
    proc = FakeProc([jline(f"c{i}") for i in range(10)])
    r = journal([proc], max_entries=3)[0].read(None, NOW)
    assert len(r.entries) == 3 and r.next_cursor == "c2" and proc.killed
    assert r.state == CollectorState.OK


@pytest.mark.parametrize("bad", ["--evil", "ssh", "ssh.service; rm -rf /", "-u x.service", ""])
def test_unit_names_are_validated(bad):
    with pytest.raises(ValueError):
        JournalSource([bad])


# ---------------------------------------------------------------- syslog parsing
@pytest.fixture
def tz_new_york(monkeypatch):
    if not hasattr(time, "tzset"):
        pytest.skip("needs POSIX tzset")
    monkeypatch.setenv("TZ", "America/New_York")
    time.tzset()
    yield
    monkeypatch.delenv("TZ")
    time.tzset()


def test_legacy_syslog_uses_local_time_and_current_year(tz_new_york):
    ts, host, ident, msg = parse_syslog_line(f"Sep 28 19:20:40 manavpi sshd[1217]: {MSG}", NOW)
    assert ts == datetime(2026, 9, 28, 23, 20, 40, tzinfo=UTC)  # EDT is UTC-4
    assert (host, ident, msg) == ("manavpi", "sshd", MSG)


def test_single_digit_day_and_no_pid():
    ts, _, ident, _ = parse_syslog_line("Sep  8 07:00:01 pi sshd-session: hello", NOW)
    assert ident == "sshd-session" and ts.month == 9 and ts.day == 8


def test_december_line_read_in_january_belongs_to_last_year():
    jan = datetime(2027, 1, 2, 0, 5, tzinfo=UTC)
    ts, *_ = parse_syslog_line("Dec 31 23:59:59 pi sshd[1]: x", jan)
    assert ts.year == 2026


def test_iso_timestamps_with_offsets():
    ts, host, ident, _ = parse_syslog_line(
        "2026-09-28T19:20:40.123456-04:00 manavpi sshd-session[9]: hi", NOW
    )
    assert ts == datetime(2026, 9, 28, 23, 20, 40, 123456, tzinfo=UTC) and ident == "sshd-session"
    ts2, *_ = parse_syslog_line("2026-09-28T19:20:40+0200 pi sshd[9]: hi", NOW)
    assert ts2 == datetime(2026, 9, 28, 17, 20, 40, tzinfo=UTC)


@pytest.mark.parametrize(
    "line", ["", "garbage", "Foo 28 19:20:40 h sshd[1]: x", "Sep 99 99:99:99 h sshd[1]: x"]
)
def test_unparseable_syslog_lines(line):
    assert parse_syslog_line(line, NOW) is None


# ---------------------------------------------------------------- auth.log file
def line(minutes_ago, msg=MSG, ident="sshd"):
    ts = NOW - timedelta(minutes=minutes_ago)
    return f"{ts:%Y-%m-%dT%H:%M:%S}+00:00 manavpi {ident}[1]: {msg}\n"


@pytest.fixture
def log(tmp_path):
    return tmp_path / "auth.log"


def src_for(path, **kw):
    return AuthLogFileSource([str(path)], **kw)


def test_missing_file_is_unavailable(tmp_path):
    assert src_for(tmp_path / "nope").read(None, NOW).state == CollectorState.UNAVAILABLE


def test_first_poll_applies_lookback_and_filters_identifiers(log):
    log.write_text(line(60) + line(5) + line(4, ident="sudo") + line(3, ident="sshd-session"))
    r = src_for(log, lookback_minutes=15).read(None, NOW)
    assert len(r.entries) == 2 and r.ignored == 2  # too old + not sshd
    assert all(e.source_name == "auth_log" for e in r.entries)


def test_incremental_reads_return_only_new_lines(log):
    log.write_text(line(5))
    s = src_for(log)
    first = s.read(None, NOW)
    assert len(first.entries) == 1
    with log.open("a") as f:
        f.write(line(1) + line(0))
    second = s.read(first.next_cursor, NOW)
    assert len(second.entries) == 2
    assert s.read(second.next_cursor, NOW).entries == []
    assert len({e.entry_id for e in first.entries + second.entries}) == 3


def test_partial_line_waits_for_completion(log):
    log.write_text(line(5))
    s = src_for(log)
    cur = s.read(None, NOW).next_cursor
    complete = line(1)
    with log.open("a") as f:
        f.write(complete[:30])
    partial = s.read(cur, NOW)
    assert partial.entries == [] and partial.next_cursor == cur
    with log.open("a") as f:
        f.write(complete[30:])
    assert len(s.read(cur, NOW).entries) == 1


def test_rotation_and_truncation_restart_from_the_top(log, tmp_path):
    log.write_text(line(5) + line(4))
    s = src_for(log)
    cur = s.read(None, NOW).next_cursor
    log.rename(tmp_path / "auth.log.1")
    log.write_text(line(3))
    assert len(s.read(cur, NOW).entries) == 1  # new inode => new file read from start
    cur2 = s.read(None, NOW).next_cursor
    log.write_text(line(0))  # truncated below the saved offset
    assert len(s.read(cur2, NOW).entries) == 1


def test_initial_tail_skips_a_partial_first_line(log, monkeypatch):
    monkeypatch.setattr(AuthLogFileSource, "_INITIAL_TAIL_BYTES", 150)
    log.write_text("".join(line(9 - i) for i in range(8)))
    r = src_for(log).read(None, NOW)
    assert r.malformed == 0 and 0 < len(r.entries) < 8


def test_max_entries_continues_without_loss_or_duplicates(log):
    log.write_text("".join(line(10 - i) for i in range(10)))
    s = src_for(log, max_entries=4)
    a = s.read(None, NOW)
    b = s.read(a.next_cursor, NOW)
    c = s.read(b.next_cursor, NOW)
    ids = [e.entry_id for r in (a, b, c) for e in r.entries]
    assert len(a.entries) == 4 and len(ids) == 10 and len(set(ids)) == 10


def test_permission_denied_is_reported(log, monkeypatch):
    log.write_text(line(1))

    def deny(self, *a, **k):
        raise PermissionError

    monkeypatch.setattr(Path, "open", deny)
    r = src_for(log).read(None, NOW)
    assert r.state == CollectorState.UNAVAILABLE and "adm" in r.detail


def test_garbage_lines_are_counted_as_malformed(log):
    log.write_text("not a syslog line\n" + line(1))
    r = src_for(log).read(None, NOW)
    assert r.malformed == 1 and len(r.entries) == 1
