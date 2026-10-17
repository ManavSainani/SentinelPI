import threading
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace as NS

from sentinelpi.collectors.auth_logs import AuthLogCollector
from sentinelpi.collectors.auth_sources import SourceRead
from sentinelpi.collectors.base import CollectionResult, CollectorState, make_status
from sentinelpi.collectors.metrics import MetricsSample
from sentinelpi.collectors.ports import PortSnapshot
from sentinelpi.collectors.processes import ProcessSnapshot
from sentinelpi.config import MonitorSettings, Settings
from sentinelpi.monitor import HEARTBEAT_KEY, Monitor
from sentinelpi.storage import events_repo, state_repo, telemetry_repo


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


class Calls:
    def __init__(self, fail=None):
        self.n = {"metrics": 0, "processes": 0, "ports": 0}
        self.fail = fail

    def collectors(self):
        def metrics():
            self.n["metrics"] += 1
            if self.fail == "metrics":
                raise RuntimeError("/secret")
            return CollectionResult[MetricsSample](
                status=make_status("metrics", CollectorState.OK),
                data=MetricsSample(
                    timestamp=datetime.now(UTC),
                    cpu_percent=1,
                    memory_percent=2,
                    disk_percent=3,
                    uptime_seconds=4,
                ),
            )

        def processes():
            self.n["processes"] += 1
            return CollectionResult[ProcessSnapshot](
                status=make_status("processes", CollectorState.OK),
                data=ProcessSnapshot(
                    timestamp=datetime.now(UTC), total_count=0, truncated=False, processes=[]
                ),
            )

        def ports():
            self.n["ports"] += 1
            return CollectionResult[PortSnapshot](
                status=make_status("ports", CollectorState.OK),
                data=PortSnapshot(
                    timestamp=datetime.now(UTC), total_count=0, truncated=False, ports=[]
                ),
            )

        return NS(
            metrics=NS(collect=metrics), processes=NS(collect=processes), ports=NS(collect=ports)
        )


class QuietSource:
    name = "journal"

    def read(self, cursor, now):
        return SourceRead(CollectorState.OK, next_cursor=cursor)


def make(db, calls=None, clock=None, **intervals):
    calls = calls or Calls()
    clock = clock or Clock()
    settings = Settings(monitor=MonitorSettings(**intervals))
    mon = Monitor(
        settings,
        db,
        collectors=calls.collectors(),
        auth_collector=AuthLogCollector([QuietSource()]),
        clock=clock,
    )
    return mon, calls, clock


def names(results):
    return [r.task for r in results]


def test_first_cycle_runs_every_task_in_collect_then_judge_order(db):
    mon, calls, _ = make(db)
    assert names(mon.run_due()) == ["metrics", "snapshots", "auth", "detection", "retention"]
    assert all(r.ok for r in mon.last_results.values())
    with db.session() as c:
        assert telemetry_repo.latest_metrics(c) is not None
        assert state_repo.get_state(c, HEARTBEAT_KEY) is not None


def test_tasks_run_on_their_own_intervals(db):
    mon, calls, clock = make(
        db,
        metrics_interval_seconds=10,
        snapshot_interval_seconds=60,
        auth_interval_seconds=15,
        detection_interval_seconds=30,
    )
    mon.run_due()
    clock.t += 5
    assert mon.run_due() == []
    clock.t += 5  # +10 s
    assert names(mon.run_due()) == ["metrics"]
    clock.t += 5  # +15 s
    assert names(mon.run_due()) == ["auth"]
    clock.t += 15  # +30 s
    assert set(names(mon.run_due())) == {"metrics", "auth", "detection"}
    clock.t += 30  # +60 s
    assert "snapshots" in names(mon.run_due())
    assert calls.n["processes"] == 2 and calls.n["metrics"] >= 4


def test_a_long_pause_does_not_cause_a_burst_of_catch_up_runs(db):
    mon, calls, clock = make(db)
    mon.run_due()
    clock.t += 10_000  # laptop slept
    mon.run_due()
    assert calls.n["metrics"] == 2  # once, not 1000 times


def test_a_failing_task_is_isolated_and_reports_type_only(db):
    mon, calls, _ = make(db, calls=Calls(fail="metrics"))
    results = mon.run_due()
    by = {r.task: r for r in results}
    assert by["metrics"].ok is False and by["metrics"].detail == "RuntimeError"
    assert by["snapshots"].ok and by["detection"].ok  # the rest still ran
    assert "secret" not in str(by["metrics"])


def test_run_all_once_ignores_the_schedule(db):
    mon, _, _ = make(db)
    mon.run_due()
    assert len(mon.run_all_once()) == 5


def test_run_forever_stops_promptly_when_asked(db):
    mon, calls, _ = make(db)
    stop = threading.Event()
    original = mon.engine.run

    def run_then_stop(*a, **k):
        stop.set()
        return original(*a, **k)

    mon.engine.run = run_then_stop
    thread = threading.Thread(target=mon.run_forever, args=(stop, 0.0))
    thread.start()
    thread.join(timeout=5)
    assert not thread.is_alive() and calls.n["metrics"] >= 1


def test_run_forever_exits_during_warmup_if_already_stopped(db):
    mon, calls, _ = make(db)
    stop = threading.Event()
    stop.set()
    mon.run_forever(stop, warmup_seconds=5.0)
    assert calls.n["metrics"] == 0


def test_attack_in_the_database_becomes_an_alert_via_the_monitor(db):
    from tests.helpers_detection import burst

    now = datetime.now(UTC)
    with db.session() as c:
        events_repo.insert_events(c, burst(now - timedelta(seconds=60), 6, step_seconds=5))
    mon, _, clock = make(db)
    mon.run_due()
    with db.session() as c:
        found = events_repo.list_events(c, event_type="detection.ssh_repeated_failures")
    assert len(found) == 1
    clock.t += 30
    mon.run_due()  # next evaluation: same attack, must not alert again
    with db.session() as c:
        assert len(events_repo.list_events(c, event_type="detection.ssh_repeated_failures")) == 1


def test_real_collectors_survive_a_full_cycle(db):
    mon = Monitor(Settings(), db, auth_collector=AuthLogCollector([QuietSource()]))
    results = mon.run_all_once()
    assert [r.task for r in results] == ["metrics", "snapshots", "auth", "detection", "retention"]
    assert all(r.ok for r in results), [r for r in results if not r.ok]
