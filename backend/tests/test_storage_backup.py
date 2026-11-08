import sqlite3
from contextlib import closing

import pytest

from sentinelpi.storage.__main__ import main
from sentinelpi.storage.backup import BackupError, backup_database, restore_database
from sentinelpi.storage.db import Database


@pytest.fixture
def live(tmp_path, monkeypatch):
    path = tmp_path / "live.db"
    cfg = tmp_path / "c.toml"
    cfg.write_text(f'[storage]\ndb_path = "{path}"\n')
    monkeypatch.setenv("SENTINELPI_CONFIG", str(cfg))
    main(["seed-events", "10"])
    return path


def _events(path):
    with closing(sqlite3.connect(path)) as c:
        return c.execute("SELECT COUNT(*) FROM events").fetchone()[0]


def test_backup_then_restore_round_trip(live, tmp_path, capsys):
    bak = tmp_path / "bk" / "copy.db"
    assert main(["backup", str(bak)]) == 0
    assert "verified" in capsys.readouterr().out
    with sqlite3.connect(live) as c:  # the live DB moves on after the backup
        c.execute("DELETE FROM events WHERE rowid IN (SELECT rowid FROM events LIMIT 4)")
    assert _events(live) == 6
    assert main(["restore", str(bak), "--replace"]) == 0
    assert _events(live) == 10
    kept = list(tmp_path.glob("live.db.before-restore-*"))
    assert len(kept) == 1 and _events(kept[0]) == 6  # the replaced database is not lost
    Database(live).migrate()  # and the restored file is a working database


def test_backup_refuses_to_overwrite(live, tmp_path):
    bak = tmp_path / "copy.db"
    backup_database(live, bak)
    with pytest.raises(BackupError, match="already exists"):
        backup_database(live, bak)


def test_restore_refuses_without_replace(live, tmp_path):
    bak = tmp_path / "copy.db"
    backup_database(live, bak)
    with pytest.raises(BackupError, match="--replace"):
        restore_database(bak, live)


def test_restore_rejects_garbage_and_foreign_databases(live, tmp_path):
    junk = tmp_path / "junk.db"
    junk.write_bytes(b"this is not sqlite" * 100)
    with pytest.raises(BackupError):
        restore_database(junk, live, replace=True)
    other = tmp_path / "other.db"
    with closing(sqlite3.connect(other)) as c:
        c.execute("CREATE TABLE x (a)")
        c.commit()
    with pytest.raises(BackupError, match="not a SentinelPI database"):
        restore_database(other, live, replace=True)
    assert _events(live) == 10  # a refused restore leaves the live database untouched


def test_restore_rejects_a_newer_schema(live, tmp_path):
    bak = tmp_path / "newer.db"
    backup_database(live, bak)
    with closing(sqlite3.connect(bak)) as c:
        c.execute(
            "INSERT INTO schema_migrations (version, name, checksum, applied_at)"
            " VALUES (99, 'future', 'x', 'now')"
        )
        c.commit()
    with pytest.raises(BackupError, match="upgrade SentinelPI"):
        restore_database(bak, live, replace=True)


def test_missing_database_is_a_clear_error(tmp_path, monkeypatch, capsys):
    cfg = tmp_path / "c.toml"
    cfg.write_text(f'[storage]\ndb_path = "{tmp_path / "none.db"}"\n')
    monkeypatch.setenv("SENTINELPI_CONFIG", str(cfg))
    assert main(["backup", str(tmp_path / "b.db")]) == 1
    assert "database not found" in capsys.readouterr().err
    assert not (tmp_path / "none.db").exists()  # backup must not create the live DB
