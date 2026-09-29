CREATE TABLE incidents (
    id              TEXT PRIMARY KEY,
    title           TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    severity        TEXT NOT NULL CHECK (severity IN ('info','low','medium','high','critical')),
    risk_score      INTEGER NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
    status          TEXT NOT NULL DEFAULT 'open'
                    CHECK (status IN ('open','acknowledged','resolved','false_positive')),
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    resolution_note TEXT
);
CREATE INDEX idx_incidents_status ON incidents(status, updated_at);
CREATE INDEX idx_incidents_last_seen ON incidents(last_seen);

CREATE TABLE events (
    id            TEXT PRIMARY KEY,
    timestamp     TEXT NOT NULL,
    source        TEXT NOT NULL
                  CHECK (source IN ('auth_log','system_metrics','process_inventory','port_inventory','test')),
    event_type    TEXT NOT NULL,
    severity      TEXT NOT NULL CHECK (severity IN ('info','low','medium','high','critical')),
    summary       TEXT NOT NULL,
    source_ip     TEXT,
    username      TEXT,
    process_name  TEXT,
    host          TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    incident_id   TEXT REFERENCES incidents(id) ON DELETE SET NULL
);
CREATE INDEX idx_events_timestamp ON events(timestamp);
CREATE INDEX idx_events_type_time ON events(event_type, timestamp);
CREATE INDEX idx_events_source_ip ON events(source_ip, timestamp);
CREATE INDEX idx_events_incident ON events(incident_id);

CREATE TABLE incident_events (
    incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    event_id    TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    PRIMARY KEY (incident_id, event_id)
);
CREATE INDEX idx_incident_events_event ON incident_events(event_id);

CREATE TABLE system_metrics (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT NOT NULL,
    cpu_percent     REAL NOT NULL,
    memory_percent  REAL NOT NULL,
    disk_percent    REAL NOT NULL,
    temperature_c   REAL,
    uptime_seconds  REAL NOT NULL,
    net_rx_bytes    INTEGER,
    net_tx_bytes    INTEGER
);
CREATE INDEX idx_system_metrics_timestamp ON system_metrics(timestamp);

CREATE TABLE process_snapshots (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp        TEXT NOT NULL,
    pid              INTEGER NOT NULL,
    name             TEXT NOT NULL,
    username         TEXT,
    cpu_percent      REAL NOT NULL,
    memory_percent   REAL NOT NULL,
    command_redacted TEXT NOT NULL
);
CREATE INDEX idx_process_snapshots_timestamp ON process_snapshots(timestamp);

CREATE TABLE listening_ports (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    observed_at    TEXT NOT NULL,
    protocol       TEXT NOT NULL CHECK (protocol IN ('tcp','udp')),
    local_address  TEXT NOT NULL,
    port           INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    process_name   TEXT,
    pid            INTEGER
);
CREATE INDEX idx_listening_ports_observed ON listening_ports(observed_at);
CREATE INDEX idx_listening_ports_key ON listening_ports(protocol, local_address, port);

CREATE TABLE detection_rules (
    id             TEXT PRIMARY KEY,
    name           TEXT NOT NULL,
    enabled        INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0,1)),
    severity       TEXT NOT NULL CHECK (severity IN ('info','low','medium','high','critical')),
    threshold_json TEXT NOT NULL DEFAULT '{}',
    description    TEXT NOT NULL DEFAULT ''
);
