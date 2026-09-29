from datetime import timedelta

from sentinelpi.collectors import HostTelemetry
from sentinelpi.collectors.base import CollectionResult, CollectorState, make_status
from sentinelpi.collectors.metrics import MetricsSample
from sentinelpi.collectors.ports import ListeningPort, PortSnapshot
from sentinelpi.collectors.processes import ProcessInfo, ProcessSnapshot
from sentinelpi.storage import telemetry_repo as repo
from sentinelpi.storage.ingest import store_telemetry
from sentinelpi.synthetic import generate_metrics
from tests.conftest import NOW


def sample(ts=NOW, **over):
    base = {
        "timestamp": ts,
        "cpu_percent": 10.0,
        "memory_percent": 20.0,
        "disk_percent": 30.0,
        "temperature_c": 50.5,
        "uptime_seconds": 1000.0,
        "net_rx_bytes": 5,
        "net_tx_bytes": 6,
    }
    base.update(over)
    return MetricsSample(**base)


def test_metrics_roundtrip_including_missing_optionals(conn):
    full, sparse = (
        sample(NOW),
        sample(NOW + timedelta(seconds=10), temperature_c=None, net_rx_bytes=None),
    )
    repo.insert_metrics(conn, full)
    repo.insert_metrics(conn, sparse)
    assert repo.latest_metrics(conn) == sparse
    assert repo.list_metrics(conn) == [full, sparse]


def test_latest_metrics_empty(conn):
    assert repo.latest_metrics(conn) is None


def test_metric_window_and_bounds_oldest_first(conn):
    repo.insert_metrics_many(conn, generate_metrics(100, start=NOW))
    got = repo.list_metrics(
        conn, since=NOW + timedelta(seconds=100), until=NOW + timedelta(seconds=150)
    )
    assert [s.timestamp for s in got] == sorted(s.timestamp for s in got) and len(got) == 5
    # limit keeps the MOST RECENT rows, still returned in chart (ascending) order
    recent = repo.list_metrics(conn, limit=3)
    assert [s.timestamp for s in recent] == [NOW + timedelta(seconds=s) for s in (970, 980, 990)]
    assert len(repo.list_metrics(conn, limit=10**9)) == 100
    assert len(repo.list_metrics(conn, limit=-5)) == 1


def proc_snap(ts, pids):
    procs = [
        ProcessInfo(
            pid=p, name=f"p{p}", cpu_percent=float(p), memory_percent=1.0, command_redacted=f"p{p}"
        )
        for p in pids
    ]
    return ProcessSnapshot(timestamp=ts, total_count=len(procs), truncated=False, processes=procs)


def test_process_snapshot_latest_wins_and_is_sorted(conn):
    repo.insert_process_snapshot(conn, proc_snap(NOW, [1, 2]))
    repo.insert_process_snapshot(conn, proc_snap(NOW + timedelta(minutes=1), [3, 9, 5]))
    ts, rows = repo.latest_process_snapshot(conn)
    assert ts == NOW + timedelta(minutes=1)
    assert [p.pid for p in rows] == [9, 5, 3]


def test_port_snapshot_latest_wins(conn):
    def snap(ts, ports):
        return PortSnapshot(timestamp=ts, total_count=len(ports), truncated=False, ports=ports)

    old = [ListeningPort(protocol="tcp", local_address="0.0.0.0", port=22)]
    new = [
        ListeningPort(
            protocol="tcp", local_address="127.0.0.1", port=8787, pid=7, process_name="py"
        ),
        ListeningPort(protocol="udp", local_address="0.0.0.0", port=68),
    ]
    repo.insert_port_snapshot(conn, snap(NOW, old))
    repo.insert_port_snapshot(conn, snap(NOW + timedelta(minutes=1), new))
    ts, rows = repo.latest_port_snapshot(conn)
    assert ts == NOW + timedelta(minutes=1)
    assert sorted(p.port for p in rows) == [68, 8787]
    assert repo.latest_port_snapshot(conn) is not None


def test_empty_snapshots_return_none(conn):
    assert repo.latest_process_snapshot(conn) is None
    assert repo.latest_port_snapshot(conn) is None


def test_store_telemetry_persists_available_and_reports_skipped(conn):
    ok = CollectionResult[MetricsSample](
        status=make_status("metrics", CollectorState.OK), data=sample()
    )
    procs = CollectionResult[ProcessSnapshot](
        status=make_status("processes", CollectorState.OK), data=proc_snap(NOW, [1, 2, 3])
    )
    failed = CollectionResult[PortSnapshot](
        status=make_status("ports", CollectorState.ERROR, "OSError")
    )
    report = store_telemetry(conn, HostTelemetry(metrics=ok, processes=procs, ports=failed))
    assert report.metrics_stored and report.process_rows == 3 and report.port_rows == 0
    assert report.skipped == ["ports"]
    assert repo.latest_metrics(conn) is not None
