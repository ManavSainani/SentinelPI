import os
import sqlite3

import pytest

from sentinelpi.storage import migrations
from sentinelpi.storage.db import Database, connect
from sentinelpi.storage.migrations import Migration, MigrationError, _statements

TABLES = {
    "events",
    "incidents",
    "incident_events",
    "system_metrics",
    "process_snapshots",
    "listening_ports",
    "detection_rules",
    "schema_migrations",
    "collector_state",
    "detection_state",
    "port_baseline",
}


def test_fresh_apply_then_idempotent(tmp_path):
    db = Database(tmp_path / "a.db")
    assert db.migrate() == [1, 2, 3, 4, 5]
    assert db.migrate() == []
    with db.session() as c:
        names = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert TABLES <= names
        row = c.execute("SELECT version, checksum FROM schema_migrations").fetchone()
        assert row["version"] == 1 and len(row["checksum"]) == 64


def test_connection_pragmas(conn):
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    assert conn.execute("PRAGMA auto_vacuum").fetchone()[0] == 2  # incremental
    assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"


@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions")
def test_database_file_is_owner_only(tmp_path):
    p = tmp_path / "d" / "x.db"
    connect(p).close()
    assert p.stat().st_mode & 0o777 == 0o600


def test_modified_migration_detected(db):
    with db.session() as c:
        c.execute("UPDATE schema_migrations SET checksum = 'tampered' WHERE version = 1")
    with pytest.raises(MigrationError, match="modified"):
        db.migrate()


def test_newer_database_refused(db):
    with db.session() as c:
        c.execute("INSERT INTO schema_migrations VALUES (999, 'future', 'x', 'now')")
    with pytest.raises(MigrationError, match="newer"):
        db.migrate()


def test_failed_migration_rolls_back_completely(tmp_path, monkeypatch):
    good = migrations.load_migrations()[0]
    bad = Migration(2, "bad", "CREATE TABLE half_done (x INTEGER);\nTHIS IS NOT SQL;", "c2")
    monkeypatch.setattr(migrations, "load_migrations", lambda: [good, bad])
    db = Database(tmp_path / "b.db")
    with pytest.raises(sqlite3.Error):
        db.migrate()
    with db.session() as c:
        names = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert "half_done" not in names  # transactional DDL: nothing leaked
        assert [r[0] for r in c.execute("SELECT version FROM schema_migrations")] == [1]


def test_statement_splitter_handles_triggers_and_comments():
    sql = (
        "CREATE TABLE t (x);\n-- note\nCREATE TRIGGER g AFTER INSERT ON t BEGIN\n"
        "  UPDATE t SET x = 1;\n  UPDATE t SET x = 2;\nEND;\n-- trailing comment\n"
    )
    assert len(_statements(sql)) == 2
    with pytest.raises(MigrationError):
        _statements("CREATE TABLE t (x")


def test_check_constraints_enforced(conn):
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO events (id,timestamp,source,event_type,severity,summary,host)"
            " VALUES ('1','t','test','x','catastrophic','s','h')"
        )
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO incidents (id,title,severity,status,first_seen,last_seen,created_at,"
            "updated_at) VALUES ('i','t','low','deleted','a','a','a','a')"
        )
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO incidents (id,title,severity,risk_score,first_seen,last_seen,created_at,"
            "updated_at) VALUES ('i','t','low',101,'a','a','a','a')"
        )


def test_incident_delete_releases_events_and_links(conn):
    conn.execute(
        "INSERT INTO incidents (id,title,severity,first_seen,last_seen,created_at,updated_at)"
        " VALUES ('i1','t','low','a','a','a','a')"
    )
    conn.execute(
        "INSERT INTO events (id,timestamp,source,event_type,severity,summary,host,incident_id)"
        " VALUES ('e1','t','test','x','low','s','h','i1')"
    )
    conn.execute("INSERT INTO incident_events VALUES ('i1','e1')")
    conn.execute("DELETE FROM incidents WHERE id = 'i1'")
    assert conn.execute("SELECT incident_id FROM events WHERE id='e1'").fetchone()[0] is None
    assert conn.execute("SELECT COUNT(*) FROM incident_events").fetchone()[0] == 0


def test_upgrade_from_version_4_keeps_the_audit_trail(tmp_path, monkeypatch):
    all_migrations = migrations.load_migrations()
    monkeypatch.setattr(migrations, "load_migrations", lambda: all_migrations[:4])
    db = Database(tmp_path / "old.db")
    assert db.migrate() == [1, 2, 3, 4]
    with db.session() as c:
        c.execute(
            "INSERT INTO incidents (id, title, severity, first_seen, last_seen, created_at,"
            " updated_at, host, rule_ids_json, risk_breakdown_json)"
            " VALUES ('i1', 't', 'high', 'x', 'x', 'x', 'x', 'pi', '[]', '[]')"
        )
        for actor in ("system", "user"):
            c.execute(
                "INSERT INTO incident_audit (incident_id, at, kind, actor)"
                " VALUES ('i1', 'x', 'status_changed', ?)",
                (actor,),
            )
    monkeypatch.setattr(migrations, "load_migrations", lambda: all_migrations)
    assert db.migrate() == [5]
    with db.session() as c:
        assert [r[0] for r in c.execute("SELECT actor FROM incident_audit ORDER BY id")] == [
            "system",
            "user",
        ]
        c.execute(
            "INSERT INTO incident_audit (incident_id, at, kind, actor)"
            " VALUES ('i1', 'x', 'status_changed', 'button')"
        )
        assert c.execute("SELECT COUNT(*) FROM incident_audit").fetchone()[0] == 3
