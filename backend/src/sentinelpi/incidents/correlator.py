"""Group detection events into incidents.

Correlation key: (host, subject) within a time window.
  * subject = the source IP for detections that have one (SP-001);
  * subject = "host-local" for detections without one (new port, CPU, watchlisted process).
A detection joins the ACTIVE (open/acknowledged) incident with the same host and subject if
its time is within `correlation_window_minutes` of that incident's span, and the incident is
younger than `max_incident_hours`. Otherwise, if its rule may open incidents
(`open_incident_rules`), it starts a new one; supporting-only rules (SP-003 by default)
attach to a matching incident but never open one, so a CPU blip alone stays a plain event.

SP-005 (repeated suspicious activity): when one incident accumulates `escalate_distinct_rules`
different rules, its severity is raised to at least High, its score gains the independent-rule
bonus, and the escalation is recorded in the audit trail.

The correlator only READS detection events and WRITES incident bookkeeping; it never invents
or alters evidence. It is idempotent: an event already attached is never processed again.
"""

from __future__ import annotations

import logging
import sqlite3
from collections import Counter
from datetime import datetime, timedelta
from uuid import uuid4

from pydantic import BaseModel, Field

from sentinelpi.config import IncidentSettings, ScoringSettings
from sentinelpi.detection.rules.ssh_failures import evidence_ids
from sentinelpi.detection.scoring import RULE_LABELS, compute_risk
from sentinelpi.events import Event, Severity
from sentinelpi.incidents.models import Incident, IncidentStatus
from sentinelpi.storage import events_repo, incidents_repo
from sentinelpi.timeutil import utc_now

log = logging.getLogger("sentinelpi.incidents")
MAX_EVIDENCE_PER_DETECTION = 100


class CorrelationReport(BaseModel):
    ran_at: datetime
    examined: int = 0
    created: int = 0
    attached: int = 0
    escalated: int = 0
    unlinked: int = 0  # supporting detections with no incident to join (left as plain events)
    skipped: int = 0  # malformed detections (no usable rule id)
    errors: int = 0
    incident_ids: list[str] = Field(default_factory=list)


class IncidentCorrelator:
    def __init__(self, settings: IncidentSettings, scoring: ScoringSettings) -> None:
        self.settings = settings
        self.scoring = scoring
        self.window = timedelta(minutes=settings.correlation_window_minutes)
        self.max_age = timedelta(hours=settings.max_incident_hours)

    # ------------------------------------------------------------------ main entry
    def run(self, conn: sqlite3.Connection, now: datetime | None = None) -> CorrelationReport:
        now = now or utc_now()
        report = CorrelationReport(ran_at=now)
        candidates = self._candidates(conn, now)
        report.examined = len(candidates)
        for event in candidates:
            rule_id = event.metadata.get("rule_id")
            if not isinstance(rule_id, str) or rule_id not in RULE_LABELS:
                report.skipped += 1
                continue
            conn.execute("SAVEPOINT correlate")
            try:
                self._process(conn, event, rule_id, now, report)
            except Exception as exc:  # noqa: BLE001 - one bad event must not block the rest
                conn.execute("ROLLBACK TO correlate")
                report.errors += 1
                log.warning("correlation failed for one detection: %s", type(exc).__name__)
            finally:
                conn.execute("RELEASE correlate")
        return report

    def _candidates(self, conn: sqlite3.Connection, now: datetime) -> list[Event]:
        """Detection events not yet attached anywhere, recent enough to still correlate.
        Rules that may open incidents go first, so supporting evidence from the same moment
        finds the incident they just opened."""
        events = events_repo.list_events_unattached_detections(
            conn, since=now - self.window, limit=self.settings.max_events_per_run
        )

        def opens(e: Event) -> bool:
            return e.metadata.get("rule_id") in self.settings.open_incident_rules

        events.sort(key=lambda e: (not opens(e), e.timestamp, str(e.id)))
        return events

    # ------------------------------------------------------------------ one detection
    def _process(
        self,
        conn: sqlite3.Connection,
        event: Event,
        rule_id: str,
        now: datetime,
        report: CorrelationReport,
    ) -> None:
        incident = incidents_repo.find_open_match(
            conn,
            host=event.host,
            source_ip=event.source_ip,
            ts=event.timestamp,
            window=self.window,
            max_age=self.max_age,
        )
        created = False
        if incident is None:
            if rule_id not in self.settings.open_incident_rules:
                report.unlinked += 1
                return
            incident = self._new_incident(conn, event, now)
            created = True

        incidents_repo.attach_event(conn, incident.id, event.id)
        for evidence_id in evidence_ids(event)[:MAX_EVIDENCE_PER_DETECTION]:
            incidents_repo.attach_event(conn, incident.id, evidence_id)

        escalated = False
        previous_rules = set(incident.rule_ids)
        refreshed = self._refresh(conn, incident, now)
        incidents_repo.add_audit(
            conn,
            incident.id,
            now,
            "created" if created else "evidence_added",
            "system",
            detail=event.summary,
        )
        threshold = self.settings.escalate_distinct_rules
        if len(refreshed.rule_ids) >= threshold > len(previous_rules):
            incidents_repo.add_audit(
                conn,
                incident.id,
                now,
                "escalated",
                "system",
                detail=f"SP-005: {len(refreshed.rule_ids)} different rules matched "
                f"({', '.join(refreshed.rule_ids)}); severity raised to at least high",
            )
            escalated = True
        if escalated:
            report.escalated += 1
        # Counted only after everything above succeeded (a failure rolls the savepoint back).
        if created:
            report.created += 1
        else:
            report.attached += 1
        if incident.id not in report.incident_ids:
            report.incident_ids.append(incident.id)

    def _new_incident(self, conn: sqlite3.Connection, event: Event, now: datetime) -> Incident:
        incident = Incident(
            id=str(uuid4()),
            title="Incident",
            description="",
            severity=Severity.LOW,
            risk_score=0,
            status=IncidentStatus.OPEN,
            host=event.host,
            source_ip=event.source_ip,
            first_seen=event.timestamp,
            last_seen=event.timestamp,
            created_at=now,
            updated_at=now,
        )
        incidents_repo.create_incident(conn, incident)
        return incident

    # ------------------------------------------------------------------ derived fields
    def _refresh(self, conn: sqlite3.Connection, incident: Incident, now: datetime) -> Incident:
        """Recompute everything derived (rules, score, severity, title, span) from what is
        attached. Derived from the evidence every time, so it can never drift from it."""
        rule_hits = Counter(incidents_repo.attached_detection_rule_ids(conn, incident.id))
        rule_ids = sorted(rule_hits)
        risk = compute_risk(rule_ids, self.scoring)
        severity = incidents_repo.attached_max_severity(conn, incident.id)
        if len(rule_ids) >= self.settings.escalate_distinct_rules:
            severity = max(severity, Severity.HIGH, key=lambda s: s.rank)
        severity = max(severity, incident.severity, key=lambda s: s.rank)  # never lowered
        first_seen, last_seen = incidents_repo.attached_time_span(conn, incident.id)
        evidence = conn.execute(
            "SELECT COUNT(*) FROM incident_events WHERE incident_id = ?", (incident.id,)
        ).fetchone()[0]
        parts = ", ".join(
            f"{r} {RULE_LABELS[r]}" + (f" x{n}" if n > 1 else "")
            for r, n in sorted(rule_hits.items())
        )
        description = (
            f"Detections: {parts}. {evidence} evidence event(s). "
            f"Risk score {risk.score} ({risk.band}); the score is a heuristic, not a probability."
        )
        title = self._title(rule_ids, incident)
        incidents_repo.update_derived(
            conn,
            incident.id,
            title=title,
            description=description,
            severity=severity,
            risk_score=risk.score,
            rule_ids=rule_ids,
            breakdown=[c.model_dump() for c in risk.breakdown],
            first_seen=first_seen,
            last_seen=last_seen,
            now=now,
        )
        refreshed = incidents_repo.get_incident(conn, incident.id)
        assert refreshed is not None
        return refreshed

    def _title(self, rule_ids: list[str], incident: Incident) -> str:
        where = f"from {incident.source_ip}" if incident.source_ip else f"on {incident.host}"
        if len(rule_ids) >= self.settings.escalate_distinct_rules:
            return f"Repeated suspicious activity {where}"
        if len(rule_ids) == 1:
            return f"{RULE_LABELS[rule_ids[0]]} {where}"
        return f"Suspicious activity {where}"
