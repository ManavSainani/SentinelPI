-- Cooldown bookkeeping: one row per dedupe key (e.g. "SP-001:203.0.113.9").
CREATE TABLE detection_state (
    dedupe_key    TEXT PRIMARY KEY,
    rule_id       TEXT NOT NULL,
    last_fired_at TEXT NOT NULL,
    fire_count    INTEGER NOT NULL DEFAULT 1,
    last_event_id TEXT
);
CREATE INDEX idx_detection_state_fired ON detection_state(last_fired_at);

-- The approved set of listening ports (SP-002). Keyed by protocol + port, per the spec.
CREATE TABLE port_baseline (
    protocol      TEXT NOT NULL CHECK (protocol IN ('tcp','udp')),
    port          INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    local_address TEXT NOT NULL,
    process_name  TEXT,
    captured_at   TEXT NOT NULL,
    PRIMARY KEY (protocol, port)
);
