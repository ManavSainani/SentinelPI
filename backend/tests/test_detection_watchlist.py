from datetime import timedelta
from types import SimpleNamespace as NS

import pytest

from sentinelpi.collectors.processes import ProcessCollector
from sentinelpi.config import ScoringSettings
from sentinelpi.config import WatchlistRule as Cfg
from sentinelpi.detection.rules.watchlist import WatchlistRule
from sentinelpi.events import EventSource, Severity
from sentinelpi.watchlist import is_watchlisted, normalize_watchlist
from tests.conftest import NOW
from tests.helpers_detection import put_processes

SNAP = NOW - timedelta(seconds=30)


def rule(**kw):
    return WatchlistRule(Cfg(**kw), ScoringSettings(), timedelta(minutes=10))


def test_skipped_without_a_snapshot_or_when_stale(conn):
    assert "no process snapshot" in rule().evaluate(conn, NOW).skipped_reason
    put_processes(conn, NOW - timedelta(minutes=11), [(1, "nmap", "pi", 0.0, 0.1)])
    assert "stale" in rule().evaluate(conn, NOW).skipped_reason


def test_negative_no_watchlisted_process(conn):
    put_processes(conn, SNAP, [(1, "sshd", "root", 0.1, 0.2), (2, "python3", "pi", 5.0, 1.0)])
    assert rule().evaluate(conn, NOW).detections == []


def test_positive_watchlisted_process(conn):
    put_processes(conn, SNAP, [(1, "sshd", "root", 0.1, 0.2), (4242, "nmap", "pi", 12.5, 0.4)])
    res = rule().evaluate(conn, NOW)
    assert len(res.detections) == 1
    d = res.detections[0]
    e = d.event
    assert d.dedupe_key == "SP-004:nmap" and e.severity == Severity.MEDIUM
    assert e.source == EventSource.PROCESS_INVENTORY and e.process_name == "nmap"
    assert e.event_type == "detection.watchlisted_process"
    m = e.metadata
    assert m["pids"] == [4242] and m["users"] == ["pi"] and m["risk_points"] == 30
    assert m["command_redacted"] == "nmap" and m["command_line_collected"] is False
    assert m["max_cpu_percent"] == 12.5


def test_matching_is_case_insensitive_but_exact(conn):
    put_processes(
        conn,
        SNAP,
        [
            (1, "NMAP", "pi", 0, 0),
            (2, "sync", "root", 0, 0),
            (3, "ncdu", "pi", 0, 0),
            (4, "nc", "pi", 0, 0),
        ],
    )
    keys = sorted(d.dedupe_key for d in rule().evaluate(conn, NOW).detections)
    assert keys == ["SP-004:nc", "SP-004:nmap"]  # "sync" and "ncdu" contain "nc" but are not it


def test_instances_of_one_name_make_one_detection(conn):
    put_processes(
        conn, SNAP, [(30, "nc", "pi", 0, 0), (10, "nc", "root", 0, 0), (20, "nc", "pi", 0, 0)]
    )
    res = rule().evaluate(conn, NOW)
    assert len(res.detections) == 1
    m = res.detections[0].event.metadata
    assert m["instances"] == 3 and m["pids"] == [10, 20, 30] and m["users"] == ["pi", "root"]


def test_custom_watchlist(conn):
    put_processes(conn, SNAP, [(1, "nmap", "pi", 0, 0), (2, "mytool", "pi", 0, 0)])
    keys = [d.dedupe_key for d in rule(process_names=["MyTool"]).evaluate(conn, NOW).detections]
    assert keys == ["SP-004:mytool"]


def test_empty_watchlist_never_matches(conn):
    put_processes(conn, SNAP, [(1, "nmap", "pi", 0, 0)])
    assert rule(process_names=[]).evaluate(conn, NOW).detections == []


def test_linux_truncated_names_match_long_entries(conn):
    long_name = "averyveryverylongtoolname"
    put_processes(conn, SNAP, [(1, long_name[:15], "pi", 0, 0)])
    assert len(rule(process_names=[long_name]).evaluate(conn, NOW).detections) == 1


def test_watchlist_helpers():
    watch = normalize_watchlist(["  NC ", "", "Hydra"])
    assert is_watchlisted("nc", watch) and is_watchlisted("HYDRA", watch)
    assert not is_watchlisted("ncat", watch) and not is_watchlisted("nc", frozenset())


@pytest.mark.parametrize("bad", [["bad;name"], ["x" * 65], ["a\nb"], [""]])
def test_invalid_names_rejected(bad):
    with pytest.raises(ValueError):
        Cfg(process_names=bad)


# ------------------------------------------------ the collector must not miss idle matches
def fake_ps(procs):
    return NS(process_iter=lambda attrs=None: [NS(info=p) for p in procs])


def proc(pid, name, cpu):
    return {"pid": pid, "name": name, "username": "pi", "cpu_percent": cpu, "memory_percent": 0.1}


def test_idle_watchlisted_process_is_kept_even_outside_the_top_n():
    procs = [proc(i, f"busy{i}", 50.0 - i) for i in range(1, 11)] + [proc(999, "nc", 0.0)]
    without = ProcessCollector(limit=5, psutil_mod=fake_ps(procs)).collect().data
    assert 999 not in {p.pid for p in without.processes}  # the blind spot we are closing
    with_watch = (
        ProcessCollector(limit=5, psutil_mod=fake_ps(procs), watchlist=["nc"]).collect().data
    )
    assert 999 in {p.pid for p in with_watch.processes}
    assert with_watch.truncated is True and with_watch.total_count == 11


def test_watchlisted_process_already_in_top_n_is_not_duplicated():
    procs = [proc(1, "nc", 90.0), proc(2, "x", 1.0)]
    data = ProcessCollector(limit=5, psutil_mod=fake_ps(procs), watchlist=["nc"]).collect().data
    assert [p.pid for p in data.processes].count(1) == 1


def test_watchlist_extras_are_bounded():
    procs = [proc(i, "nc", 0.0) for i in range(1, 200)] + [proc(5000, "busy", 80.0)]
    data = ProcessCollector(limit=1, psutil_mod=fake_ps(procs), watchlist=["nc"]).collect().data
    assert len(data.processes) == 1 + 50


def test_end_to_end_idle_match_reaches_the_rule(conn):
    from sentinelpi.storage import telemetry_repo

    procs = [proc(i, f"busy{i}", 50.0 - i) for i in range(1, 11)] + [proc(999, "nc", 0.0)]
    snap = ProcessCollector(limit=5, psutil_mod=fake_ps(procs), watchlist=["nc"]).collect().data
    snap = snap.model_copy(update={"timestamp": SNAP})
    telemetry_repo.insert_process_snapshot(conn, snap)
    assert [d.dedupe_key for d in rule().evaluate(conn, NOW).detections] == ["SP-004:nc"]
