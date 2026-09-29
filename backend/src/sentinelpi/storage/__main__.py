"""Storage admin/verification CLI:  python -m sentinelpi.storage <command>

migrate            apply pending schema migrations
status             schema version, row counts, size
collect-once       collect one telemetry snapshot from this host and store it
seed-events [N]    insert N synthetic events (source="test"), default 25
prune              run the retention job now
"""

from __future__ import annotations

import argparse
import time
from datetime import timedelta

from sentinelpi.collectors import HostCollectors
from sentinelpi.config import load_settings
from sentinelpi.storage import events_repo
from sentinelpi.storage.db import Database
from sentinelpi.storage.ingest import store_telemetry
from sentinelpi.storage.retention import db_used_bytes, run_retention
from sentinelpi.synthetic import generate_events
from sentinelpi.timeutil import utc_now

_TABLES = (
    "events",
    "incidents",
    "incident_events",
    "system_metrics",
    "process_snapshots",
    "listening_ports",
    "detection_rules",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m sentinelpi.storage")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("migrate")
    sub.add_parser("status")
    sub.add_parser("collect-once")
    seed = sub.add_parser("seed-events")
    seed.add_argument("count", nargs="?", type=int, default=25)
    sub.add_parser("prune")
    args = parser.parse_args(argv)

    settings = load_settings()
    db = Database(settings.storage.db_path)
    applied = db.migrate()  # idempotent; every command starts from a current schema

    if args.command == "migrate":
        print(f"applied migrations: {applied or 'none (already up to date)'}")
        print(f"database: {db.path}")
    elif args.command == "status":
        with db.session() as conn:
            version = conn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0]
            print(f"database: {db.path}")
            print(f"schema version: {version}")
            print(f"used size: {db_used_bytes(conn) / 1024:.1f} KiB")
            for table in _TABLES:  # constant names, safe to interpolate
                count = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                print(f"  {table}: {count}")
    elif args.command == "collect-once":
        collectors = HostCollectors(settings.collection)
        time.sleep(1.0)  # let CPU counters accumulate
        telemetry = collectors.collect_all()
        with db.session() as conn:
            print(store_telemetry(conn, telemetry).model_dump_json(indent=2))
    elif args.command == "seed-events":
        count = max(1, min(args.count, 1000))
        start = utc_now() - timedelta(seconds=30 * count)
        with db.session() as conn:
            inserted = events_repo.insert_events(conn, generate_events(count, start=start))
        print(f"inserted {inserted} synthetic events (source='test')")
    elif args.command == "prune":
        with db.session() as conn:
            print(run_retention(conn, settings.retention).model_dump_json(indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
