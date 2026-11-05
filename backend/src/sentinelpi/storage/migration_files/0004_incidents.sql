-- Phase 6: incident correlation. Adds the correlation subject (host + optional source IP),
-- the stored score breakdown, and an append-only audit trail of everything that happens to
-- an incident (creation, new evidence, escalation, user status changes).

ALTER TABLE incidents ADD COLUMN host TEXT NOT NULL DEFAULT '';
ALTER TABLE incidents ADD COLUMN source_ip TEXT;
ALTER TABLE incidents ADD COLUMN rule_ids_json TEXT NOT NULL DEFAULT '[]';
ALTER TABLE incidents ADD COLUMN risk_breakdown_json TEXT NOT NULL DEFAULT '[]';
CREATE INDEX idx_incidents_match ON incidents(host, source_ip, status, last_seen);

CREATE TABLE incident_audit (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    at          TEXT NOT NULL,
    kind        TEXT NOT NULL
                CHECK (kind IN ('created','evidence_added','escalated','status_changed')),
    actor       TEXT NOT NULL CHECK (actor IN ('system','user')),
    from_status TEXT CHECK (from_status IS NULL
                OR from_status IN ('open','acknowledged','resolved','false_positive')),
    to_status   TEXT CHECK (to_status IS NULL
                OR to_status IN ('open','acknowledged','resolved','false_positive')),
    note        TEXT,
    detail      TEXT
);
CREATE INDEX idx_incident_audit_incident ON incident_audit(incident_id, id);
