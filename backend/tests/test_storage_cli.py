import json

import pytest

from sentinelpi.storage.__main__ import main


@pytest.fixture(autouse=True)
def cfg(tmp_path, monkeypatch):
    f = tmp_path / "c.toml"
    f.write_text(f'[storage]\ndb_path = "{tmp_path / "cli.db"}"\n')
    monkeypatch.setenv("SENTINELPI_CONFIG", str(f))


def test_migrate_then_status(capsys):
    assert main(["migrate"]) == 0
    assert "[1]" in capsys.readouterr().out
    main(["migrate"])
    assert "already up to date" in capsys.readouterr().out
    main(["status"])
    out = capsys.readouterr().out
    assert "schema version: 1" in out and "events: 0" in out


def test_seed_prune_and_status(capsys):
    main(["seed-events", "12"])
    assert "inserted 12" in capsys.readouterr().out
    main(["status"])
    assert "events: 12" in capsys.readouterr().out
    main(["prune"])
    report = json.loads(capsys.readouterr().out)
    assert report["size_target_met"] is True


def test_seed_count_is_bounded(capsys):
    main(["seed-events", "999999"])
    assert "inserted 1000" in capsys.readouterr().out


def test_collect_once_stores_live_metrics(capsys):
    main(["collect-once"])
    report = json.loads(capsys.readouterr().out)
    assert report["metrics_stored"] is True
    main(["status"])
    assert "system_metrics: 1" in capsys.readouterr().out
