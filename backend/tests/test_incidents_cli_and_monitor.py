from datetime import UTC, datetime, timedelta

import pytest

from sentinelpi.collectors.auth_logs import AuthLogCollector
from sentinelpi.config import Settings
from sentinelpi.incidents.__main__ import main
from sentinelpi.monitor import Monitor
from sentinelpi.storage import events_repo, incidents_repo
from sentinelpi.storage.db import Database
from tests.helpers_detection import burst
from tests.helpers_incidents import detection, put
from tests.test_monitor import QuietSource, make


@pytest.fixture
def cli_db(tmp_path, monkeypatch):
    f = tmp_path / "c.toml"
    f.write_text(f'[storage]\ndb_path = "{tmp_path / "cli.db"}"\n')
    monkeypatch.setenv("SENTINELPI_CONFIG", str(f))
    db = Database(tmp_path / "cli.db")
    db.migrate()
    return db


def test_cli_full_lifecycle(cli_db, capsys):
    now = datetime.now(UTC)
    with cli_db.session() as c:
        put(c, detection(now, ip="203.0.113.9"))
    assert main(["list"]) == 0 and "no incidents" in capsys.readouterr().out

    assert main(["run"]) == 0
    assert '"created": 1' in capsys.readouterr().out
    main(["list"])
    out = capsys.readouterr().out
    assert "open" in out and "203.0.113.9" in out and "Repeated SSH failures" in out
    short = out.split()[0]

    assert main(["ack", short, "--note", "looking"]) == 0
    assert main(["show", short]) == 0
    shown = capsys.readouterr().out
    assert "acknowledged" in shown and "score breakdown" in shown and "status_changed" in shown

    assert main(["resolve", short, "--note", "blocked"]) == 0
    assert main(["resolve", short]) == 1  # terminal: refused
    assert "cannot change" in capsys.readouterr().err
    main(["list", "--status", "resolved"])
    assert "resolved" in capsys.readouterr().out


def test_cli_rejects_unknown_ids(cli_db, capsys):
    assert main(["show", "deadbeef"]) == 2
    assert "no such incident" in capsys.readouterr().err
    assert main(["resolve", "%"]) == 2


def test_the_monitor_turns_an_attack_into_one_incident(db):
    now = datetime.now(UTC)
    with db.session() as c:
        events_repo.insert_events(c, burst(now - timedelta(seconds=60), 6, step_seconds=5))
    mon, _, clock = make(db)
    mon.run_due()
    for _ in range(3):  # repeated cycles: no duplicates
        clock.t += 30
        mon.run_due()
    with db.session() as c:
        incidents = incidents_repo.list_incidents(c)
    assert len(incidents) == 1 and incidents[0].rule_ids == ["SP-001"]


def test_a_correlator_crash_keeps_detections_and_is_reported(db):
    class Boom:
        def run(self, *_a, **_k):
            raise RuntimeError("/secret/path")

    now = datetime.now(UTC)
    with db.session() as c:
        events_repo.insert_events(c, burst(now - timedelta(seconds=60), 6, step_seconds=5))
    mon = Monitor(
        Settings(), db, auth_collector=AuthLogCollector([QuietSource()]), correlator=Boom()
    )
    result = mon._run_task(next(t for t in mon.tasks if t.name == "detection"))
    assert result.ok and "RuntimeError" in result.detail and "secret" not in result.detail
    with db.session() as c:
        assert len(events_repo.list_events(c, event_type="detection.ssh_repeated_failures")) == 1
