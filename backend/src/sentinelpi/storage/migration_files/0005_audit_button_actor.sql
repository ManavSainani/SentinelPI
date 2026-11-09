-- Allow the physical acknowledge button as an audited actor. SQLite cannot change a CHECK
-- constraint in place, so rebuild the table and keep every existing row.
CREATE TABLE incident_audit_new (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    at          TEXT NOT NULL,
    kind        TEXT NOT NULL
                CHECK (kind IN ('created','evidence_added','escalated','status_changed')),
    actor       TEXT NOT NULL CHECK (actor IN ('system','user','button')),
    from_status TEXT CHECK (from_status IS NULL
                OR from_status IN ('open','acknowledged','resolved','false_positive')),
    to_status   TEXT CHECK (to_status IS NULL
                OR to_status IN ('open','acknowledged','resolved','false_positive')),
    note        TEXT,
    detail      TEXT
);
INSERT INTO incident_audit_new
    SELECT id, incident_id, at, kind, actor, from_status, to_status, note, detail FROM incident_audit;
DROP TABLE incident_audit;
ALTER TABLE incident_audit_new RENAME TO incident_audit;
CREATE INDEX idx_incident_audit_incident ON incident_audit(incident_id, id);
