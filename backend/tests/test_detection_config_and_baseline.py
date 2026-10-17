import json
from datetime import timedelta

import pytest
from pydantic import ValidationError

from sentinelpi.collectors.base import CollectionResult, CollectorState, make_status
from sentinelpi.collectors.ports import ListeningPort, PortSnapshot
from sentinelpi.collectors.processes import ProcessSnapshot
from sentinelpi.config import (
    DetectionSettings,
    MonitorSettings,
    RetentionSettings,
    SshFailuresRule,
    load_settings,
)
from sentinelpi.detection import baseline
from sentinelpi.detection.__main__ import main as detection_main
from sentinelpi.storage import detection_repo, state_repo
from sentinelpi.storage.__main__ import main as storage_main
from sentinelpi.storage.db import Database
from sentinelpi.storage.ingest import store_snapshots
from sentinelpi.storage.retention import run_retention
from tests.conftest import NOW
from tests.helpers_detection import put_baseline, put_ports


# ------------------------------------------------------------------ configuration
def test_defaults_match_the_spec():
    d = DetectionSettings()
    assert (d.ssh_failures.threshold, d.ssh_failures.window_minutes) == (5, 5)
    assert (d.cpu.cpu_percent, d.cpu.window_minutes) == (90.0, 5)
    assert "nc" in d.watchlist.process_names and d.new_port.protocols == ["tcp", "udp"]
    assert MonitorSettings().metrics_interval_seconds == 10


def test_a_typo_in_the_config_fails_loudly(tmp_path):
    f = tmp_path / "c.toml"
    f.write_text("[detection.ssh_failures]\nthreshhold = 3\n")  # misspelled
    with pytest.raises(ValidationError):
        load_settings(f)
    f.write_text("[detection.ssh_failure]\nthreshold = 3\n")  # wrong section
    with pytest.raises(ValidationError):
        load_settings(f)


def test_toml_overrides_are_applied(tmp_path):
    f = tmp_path / "c.toml"
    f.write_text(
        "[detection.ssh_failures]\nthreshold = 8\nignored_source_ips = ['192.168.4.25']\n"
        "[detection.cpu]\ncpu_percent = 80\n[monitor]\nmetrics_interval_seconds = 5\n"
    )
    s = load_settings(f)
    assert s.detection.ssh_failures.threshold == 8 and s.detection.cpu.cpu_percent == 80
    assert s.detection.ssh_failures.ignored_source_ips == ["192.168.4.25"]
    assert s.monitor.metrics_interval_seconds == 5


def test_ip_allowlist_is_validated_and_normalized():
    assert SshFailuresRule(ignored_source_ips=["2001:DB8::0001"]).ignored_source_ips == [
        "2001:db8::1"
    ]
    with pytest.raises(ValidationError):
        SshFailuresRule(ignored_source_ips=["not-an-ip"])


@pytest.mark.parametrize(
    "bad",
    [
        {"metrics_interval_seconds": 0},
        {"detection_interval_seconds": 1},
        {"retention_interval_seconds": 5},
    ],
)
def test_monitor_intervals_are_bounded(bad):
    with pytest.raises(ValidationError):
        MonitorSettings(**bad)


# ------------------------------------------------------------------ ingest coverage
def snap(ts, ports):
    items = [ListeningPort(protocol=p, port=n, local_address="0.0.0.0") for p, n in ports]
    return PortSnapshot(timestamp=ts, total_count=len(items), truncated=False, ports=items)


def results(ports_missing):
    procs = CollectionResult[ProcessSnapshot](
        status=make_status("processes", CollectorState.OK),
        data=ProcessSnapshot(timestamp=NOW, total_count=0, truncated=False, processes=[]),
    )
    state = CollectorState.DEGRADED if ports_missing else CollectorState.OK
    ports = CollectionResult[PortSnapshot](
        status=make_status("ports", state, missing=ports_missing), data=snap(NOW, [("tcp", 22)])
    )
    return procs, ports


def test_ingest_records_which_protocols_were_visible(conn):
    store_snapshots(conn, *results([]))
    assert state_repo.get_state(conn, detection_repo.COVERAGE_KEY) == "tcp,udp"
    store_snapshots(conn, *results(["udp", "other_users_processes"]))
    assert state_repo.get_state(conn, detection_repo.COVERAGE_KEY) == "tcp"


# ------------------------------------------------------------------ baseline capture
def test_capture_requires_a_fresh_snapshot(conn):
    with pytest.raises(baseline.BaselineError, match="no port snapshot"):
        baseline.candidate(conn, NOW)
    put_ports(conn, NOW - timedelta(minutes=11), [("tcp", 22, "0.0.0.0", "sshd")])
    with pytest.raises(baseline.BaselineError, match="10 minutes old"):
        baseline.candidate(conn, NOW)


def test_capture_stores_ports_and_observed_protocols(conn):
    put_ports(
        conn,
        NOW - timedelta(seconds=20),
        [
            ("tcp", 22, "0.0.0.0", "sshd"),
            ("tcp", 22, "::", "sshd"),
            ("udp", 68, "0.0.0.0", "dhcpcd"),
        ],
    )
    state_repo.set_state(conn, detection_repo.COVERAGE_KEY, "tcp,udp")
    meta = baseline.capture(conn, NOW)
    assert meta.count == 2 and meta.protocols == ["tcp", "udp"]
    assert detection_repo.get_baseline_keys(conn) == {("tcp", 22), ("udp", 68)}
    row = detection_repo.list_baseline(conn)[0]
    assert row["local_address"] == "0.0.0.0,::" and row["process_name"] == "sshd"


def test_unknown_coverage_defaults_to_tcp_only(conn):
    put_ports(conn, NOW - timedelta(seconds=20), [("tcp", 22, "0.0.0.0", "sshd")])
    assert baseline.capture(conn, NOW).protocols == ["tcp"]


def test_recapture_replaces_the_previous_baseline(conn):
    put_baseline(conn, NOW - timedelta(days=2), [("tcp", 1111, "0.0.0.0", None)])
    put_ports(conn, NOW - timedelta(seconds=20), [("tcp", 22, "0.0.0.0", "sshd")])
    baseline.capture(conn, NOW)
    assert detection_repo.get_baseline_keys(conn) == {("tcp", 22)}


# ------------------------------------------------------------------ CLIs
@pytest.fixture
def cli(tmp_path, monkeypatch):
    f = tmp_path / "c.toml"
    f.write_text(f'[storage]\ndb_path = "{tmp_path / "cli.db"}"\n')
    monkeypatch.setenv("SENTINELPI_CONFIG", str(f))
    return Database(tmp_path / "cli.db")


def test_rules_and_score_commands(cli, capsys):
    assert detection_main(["rules"]) == 0
    out = capsys.readouterr().out
    for rid in ("SP-001", "SP-002", "SP-003", "SP-004"):
        assert rid in out
    assert detection_main(["score", "SP-001", "SP-004"]) == 0
    assert json.loads(capsys.readouterr().out)["score"] == 75


def test_run_command_reports_every_rule(cli, capsys):
    detection_main(["run"])
    report = json.loads(capsys.readouterr().out)
    assert [r["rule_id"] for r in report["rules"]] == ["SP-001", "SP-002", "SP-003", "SP-004"]


def test_baseline_capture_flow_through_the_cli(cli, capsys, monkeypatch):
    assert detection_main(["baseline", "capture", "--yes"]) == 1  # nothing collected yet
    assert "cannot capture baseline" in capsys.readouterr().err
    storage_main(["collect-once"])
    capsys.readouterr()
    monkeypatch.setattr("builtins.input", lambda _: "n")
    assert detection_main(["baseline", "capture"]) == 1
    assert "not approved" in capsys.readouterr().out
    detection_main(["baseline", "show"])
    assert "no baseline" in capsys.readouterr().out
    monkeypatch.setattr("builtins.input", lambda _: "y")
    assert detection_main(["baseline", "capture"]) == 0
    assert "baseline saved" in capsys.readouterr().out
    detection_main(["baseline", "show"])
    assert "captured at" in capsys.readouterr().out


# ------------------------------------------------------------------ retention
def test_old_cooldown_records_are_pruned_recent_ones_kept(conn):
    from uuid import uuid4

    detection_repo.record_fired(conn, "SP-001:old", "SP-001", uuid4(), NOW - timedelta(days=30))
    detection_repo.record_fired(conn, "SP-001:new", "SP-001", uuid4(), NOW - timedelta(days=1))
    run_retention(conn, RetentionSettings(events_days=14), now=NOW)
    assert detection_repo.get_last_fired(conn, "SP-001:old") is None
    assert detection_repo.get_last_fired(conn, "SP-001:new") is not None


def test_the_documented_example_config_is_valid_and_matches_the_defaults():
    from pathlib import Path

    example = Path(__file__).resolve().parents[2] / "config" / "sentinelpi.example.toml"
    loaded = load_settings(example)
    assert loaded.detection == DetectionSettings()
    assert loaded.monitor == MonitorSettings()
