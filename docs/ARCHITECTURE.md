# Architecture

SentinelPI is two processes sharing one SQLite database. The **monitor** writes; the **API**
mostly reads and serves the dashboard. Neither takes any action against the host: it observes
and explains.

```mermaid
flowchart LR
  subgraph Host["Monitored host (Raspberry Pi)"]
    PS["psutil: CPU, memory, disk,<br/>processes, listening ports"]
    J["systemd journal / auth.log<br/>(sshd entries)"]
  end
  subgraph Monitor["sentinelpi-monitor"]
    C["Collectors"] --> N["Normalise to events<br/>(no passwords, no usernames<br/>for unknown accounts)"]
    N --> D["Detection rules<br/>SP-001 to SP-004"]
    D --> I["Incident correlator<br/>+ SP-005 escalation"]
    R["Retention pruning"]
  end
  DB[("SQLite (WAL)<br/>events, incidents, audit,<br/>metrics, snapshots")]
  subgraph API["sentinelpi-api (127.0.0.1:8787)"]
    F["FastAPI /api/v1"] --> S["Static React build"]
  end
  PS --> C
  J --> C
  N --> DB
  D --> DB
  I --> DB
  R --> DB
  DB --> F
  S --> B["Browser: dashboard"]
  S --> K["Chromium kiosk on the HDMI monitor"]
```

## Data flow of one detection
```mermaid
sequenceDiagram
  participant L as Auth log
  participant M as Monitor
  participant DB as SQLite
  participant A as API
  participant K as Kiosk
  L->>M: 5+ "Failed password" lines from one IP
  M->>DB: auth.ssh_failed_login events (deduplicated by log entry)
  M->>DB: detection.ssh_repeated_failures (SP-001, cooldown per IP)
  M->>DB: incident opened or joined, evidence linked, audit entry
  K->>A: poll /system/status every 5 s
  A->>DB: most severe open, unacknowledged incident
  A-->>K: active_alert
  K->>K: High or above goes full screen
```

## Components
| Area | Where | Notes |
|---|---|---|
| Collectors | `backend/src/sentinelpi/collectors/` | Metrics, processes, ports; auth source is journald first, file fallback. Each reports `ok / unavailable / error` instead of failing the loop. |
| Events | `events.py`, `storage/events_repo.py` | One Pydantic model; ids are deterministic so re-reading a log never duplicates. |
| Detection | `detection/rules/` | One class per rule: thresholds, cooldown, evidence. Rule outputs are events too. |
| Correlation | `incidents/` | Key is (host, subject); idempotent; per-event savepoints. |
| Storage | `storage/` | Plain SQL, ordered migrations with checksums, WAL, retention and size cap. |
| API | `api/` | Versioned `/api/v1`, keyset pagination, one error shape, host and origin checks. |
| Frontend | `frontend/src/` | React + TypeScript, polling hooks, hand-drawn SVG charts, no chart library. |
| Packaging | `deploy/` | systemd units, installer, kiosk autostart. |

## Design decisions
- **SQLite, no server.** One writer and a few readers on a Pi; WAL gives concurrent reads. Backups use SQLite's online backup API.
- **Polling, not websockets.** Simple, robust to restarts, and a 5 s kiosk poll is cheap (a status request takes about 9 ms on the Pi).
- **Detections are events.** They appear in the same timeline as the evidence and flow through the same correlator.
- **No remediation.** Nothing blocks, kills or changes anything. A wrong detection can only be a wrong notification.
- **Local only.** The API binds to loopback and has no login, so it is never exposed.
