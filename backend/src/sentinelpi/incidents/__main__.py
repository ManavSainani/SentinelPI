"""Incident CLI.

    python -m sentinelpi.incidents run                       # correlate new detections now
    python -m sentinelpi.incidents list [--status open] [--limit 20]
    python -m sentinelpi.incidents show <id>                  # details + evidence timeline
    python -m sentinelpi.incidents ack <id>
    python -m sentinelpi.incidents resolve <id> [--note "..."]
    python -m sentinelpi.incidents false-positive <id> [--note "..."]

<id> may be the full id or any unique prefix (the first 8 characters are shown in `list`).
"""

from __future__ import annotations

import argparse
import sys

from sentinelpi.config import load_settings
from sentinelpi.incidents.correlator import IncidentCorrelator
from sentinelpi.incidents.lifecycle import (
    IncidentNotFoundError,
    TransitionError,
    change_status,
)
from sentinelpi.incidents.models import Incident, IncidentStatus
from sentinelpi.storage import incidents_repo
from sentinelpi.storage.db import Database


def _line(i: Incident) -> str:
    who = i.source_ip or "local"
    return (
        f"{i.id[:8]}  {i.status.value:<14} {i.severity.value:<8} risk {i.risk_score:>3}  "
        f"{i.last_seen:%Y-%m-%d %H:%M}Z  {who:<15} {i.title}"
    )


def _show(conn, incident_id: str) -> None:
    i = incidents_repo.get_incident(conn, incident_id)
    assert i is not None
    print(f"{i.title}")
    print(f"  id        {i.id}")
    print(f"  status    {i.status.value}    severity {i.severity.value}    risk {i.risk_score}")
    print(f"  host      {i.host}    source {i.source_ip or 'host-local'}")
    print(f"  seen      {i.first_seen:%Y-%m-%d %H:%M:%S}Z -> {i.last_seen:%Y-%m-%d %H:%M:%S}Z")
    print(f"  rules     {', '.join(i.rule_ids) or '-'}    evidence events: {i.evidence_count}")
    print(f"  summary   {i.description}")
    if i.resolution_note:
        print(f"  note      {i.resolution_note}")
    print("  score breakdown:")
    for c in i.risk_breakdown:
        print(f"    {c['points']:>+4}  {c['label']}")
    print("  timeline (oldest first):")
    for item in incidents_repo.get_timeline(conn, i.id, limit=200):
        stamp = f"{item.at:%H:%M:%S}"
        if item.kind == "event":
            tag = (item.event_type or "").replace("detection.", "DETECTION ")
            sev = item.severity.value if item.severity else "-"
            print(f"    {stamp}  [{sev}] {tag}: {item.summary}")
        else:
            change = f" {item.from_status}->{item.to_status}" if item.to_status else ""
            text = item.note or item.summary
            extra = f" - {text}" if text else ""
            print(f"    {stamp}  <{item.actor}> {item.audit_kind}{change}{extra}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m sentinelpi.incidents")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("run", help="correlate new detection events into incidents")
    p_list = sub.add_parser("list", help="list incidents, most recently active first")
    p_list.add_argument("--status", choices=[s.value for s in IncidentStatus])
    p_list.add_argument("--limit", type=int, default=20)
    for name, helptext in (
        ("show", "show an incident with its evidence timeline"),
        ("ack", "acknowledge an incident"),
        ("resolve", "mark an incident resolved"),
        ("false-positive", "mark an incident as a false positive"),
    ):
        p = sub.add_parser(name, help=helptext)
        p.add_argument("incident_id")
        if name in ("resolve", "false-positive", "ack"):
            p.add_argument("--note", help="optional note stored in the audit trail")
    args = parser.parse_args(argv)

    settings = load_settings()
    db = Database(settings.storage.db_path)
    db.migrate()
    with db.session() as conn:
        if args.command == "run":
            report = IncidentCorrelator(settings.incidents, settings.detection.scoring).run(conn)
            print(report.model_dump_json(indent=2))
            return 0
        if args.command == "list":
            status = IncidentStatus(args.status) if args.status else None
            rows = incidents_repo.list_incidents(conn, status=status, limit=args.limit)
            print("\n".join(_line(i) for i in rows) if rows else "no incidents")
            return 0

        try:
            incident_id = incidents_repo.resolve_id(conn, args.incident_id)
        except incidents_repo.AmbiguousIdError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        if incident_id is None:
            print("no such incident", file=sys.stderr)
            return 2
        if args.command == "show":
            _show(conn, incident_id)
            return 0
        target = {
            "ack": IncidentStatus.ACKNOWLEDGED,
            "resolve": IncidentStatus.RESOLVED,
            "false-positive": IncidentStatus.FALSE_POSITIVE,
        }[args.command]
        try:
            updated = change_status(conn, incident_id, target, note=args.note)
        except (TransitionError, IncidentNotFoundError) as exc:
            print(str(exc), file=sys.stderr)
            return 1
        print(_line(updated))
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
