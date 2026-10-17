"""Detection CLI:  python -m sentinelpi.detection <command>

rules                      list the rules with their effective thresholds
run                        evaluate all rules once against the database now
baseline show              show the approved listening-port baseline
baseline capture [--yes]   review the current listening ports and approve them as baseline
score SP-001 SP-004 ...    preview the risk score for a set of matched rules
"""

from __future__ import annotations

import argparse
import json
import sys

from sentinelpi.config import load_settings
from sentinelpi.detection import baseline
from sentinelpi.detection.engine import DetectionEngine
from sentinelpi.detection.scoring import compute_risk
from sentinelpi.storage import detection_repo
from sentinelpi.storage.db import Database


def _row(protocol: str, port: int, address: str, process: str | None) -> str:
    return f"  {protocol}/{port:<6} {address:<24} {process or '-'}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m sentinelpi.detection")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("rules")
    sub.add_parser("run")
    b = sub.add_parser("baseline")
    b_sub = b.add_subparsers(dest="action", required=True)
    b_sub.add_parser("show")
    cap = b_sub.add_parser("capture")
    cap.add_argument("--yes", action="store_true", help="approve without prompting")
    sc = sub.add_parser("score")
    sc.add_argument("rule_ids", nargs="+")
    args = parser.parse_args(argv)

    settings = load_settings()
    if args.command == "score":
        print(compute_risk(args.rule_ids, settings.detection.scoring).model_dump_json(indent=2))
        return 0

    db = Database(settings.storage.db_path)
    db.migrate()
    engine = DetectionEngine(settings.detection)

    if args.command == "rules":
        for rule in engine.rules:
            entry = rule.catalog_entry()
            state = "enabled" if entry["enabled"] else "DISABLED"
            print(f"{entry['id']}  {entry['name']}  [{entry['severity']}, {state}]")
            print(f"    {entry['description']}")
            print(f"    thresholds: {json.dumps(entry['thresholds'])}")
    elif args.command == "run":
        with db.session() as conn:
            print(engine.run(conn).model_dump_json(indent=2))
    elif args.command == "baseline" and args.action == "show":
        with db.session() as conn:
            meta = detection_repo.get_baseline_meta(conn)
            if meta is None:
                print("no baseline captured yet")
                return 0
            print(
                f"captured at {meta.captured_at.isoformat()}; protocols observed: {meta.protocols}"
            )
            for r in detection_repo.list_baseline(conn):
                print(_row(r["protocol"], r["port"], r["local_address"], r["process_name"]))
    elif args.command == "baseline" and args.action == "capture":
        with db.session() as conn:
            try:
                cand = baseline.candidate(conn)
            except baseline.BaselineError as exc:
                print(f"cannot capture baseline: {exc}", file=sys.stderr)
                return 1
            keys = sorted({(p.protocol, p.port) for p in cand.ports})
            print(f"Listening ports in the snapshot taken at {cand.observed_at.isoformat()}:")
            for p in sorted(cand.ports, key=lambda x: (x.protocol, x.port, x.local_address)):
                print(_row(p.protocol, p.port, p.local_address, p.process_name))
            print(f"\n{len(keys)} port(s); protocols observed: {cand.protocols}")
            print("These will be treated as NORMAL; anything new will raise SP-002.")
            if not args.yes and input("Approve this baseline? [y/N] ").strip().lower() != "y":
                print("not approved; baseline unchanged")
                return 1
            meta = baseline.capture(conn)
            print(f"baseline saved: {meta.count} port(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
