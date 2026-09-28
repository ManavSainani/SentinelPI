**SENTINELPI**

**Raspberry Pi Security Monitoring & Incident Response Platform**

**MASTER PROJECT OUTLINE • CLAUDE BUILD GUIDE**

A step-by-step implementation specification from initial setup through testing, documentation, and portfolio presentation.

| **PROJECT GOAL** Build a secure, lightweight monitoring appliance on a Raspberry Pi 4 that collects host telemetry, detects suspicious activity, groups related events into incidents, and presents the results in a web dashboard. |
|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|

| **Project facts** | **Decision**                                                                              |
|-------------------|-------------------------------------------------------------------------------------------|
| Hardware target   | Raspberry Pi 4 (4 GB RAM or better), 64-bit Raspberry Pi OS                               |
| Primary language  | Python 3                                                                                  |
| Backend/API       | FastAPI                                                                                   |
| Frontend          | React + TypeScript + Vite                                                                 |
| Database          | SQLite for the MVP                                                                        |
| Deployment        | Native system services first; Docker only where it helps and does not hide host telemetry |
| Project posture   | Local-first, defensive monitoring, safe-by-default                                        |
| Primary outcome   | A working, documented, demonstrable cybersecurity systems project                         |

**How to use this document**

Give this document to Claude as the source of truth. Ask it to work one phase at a time, explain decisions, create files in small coherent batches, run tests, and stop for your review at every phase gate. Do not ask it to generate the entire codebase in one response.

# 1. Project overview

SentinelPi is a self-hosted defensive security monitoring platform designed for a Raspberry Pi 4. It observes the Pi itself, turns relevant activity into normalized events, evaluates events with transparent detection rules, correlates related events into incidents, and exposes system health and security findings through a local web dashboard.

## Problem statement

Small lab environments often lack a visible, understandable way to inspect host health and security-relevant activity. SentinelPi provides a compact learning and portfolio platform for collecting telemetry, detecting a small set of suspicious patterns, investigating evidence, and documenting response.

## Portfolio objectives

- Demonstrate practical Linux and Raspberry Pi/ARM64 development.

- Show networking fundamentals, process and service monitoring, authentication logs, and event handling.

- Build a complete software system: collector, detection engine, persistence, API, UI, tests, and documentation.

- Demonstrate defensive security reasoning, threat modeling, safe configuration, and incident investigation.

- Produce a reproducible demo with measured performance and clear limitations.

## Primary user

A student, lab administrator, or developer who wants to monitor one Raspberry Pi on a trusted local network and investigate basic security events.

## Success statement

| **DONE MEANS** On a clean supported Raspberry Pi OS installation, a user can install SentinelPi, open its local dashboard, see current system metrics, generate safe test events, observe detection and incident creation, inspect the evidence, and follow the documented uninstall/recovery steps. |
|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|

# 2. MVP scope and non-goals

## Must-have MVP

- Host system metrics: CPU, memory, disk, uptime, temperature when available, and network byte counters.

- Host inventory snapshots: running processes and listening TCP/UDP ports, with collection timestamps.

- Security event ingestion from supported local Linux authentication/system logs; gracefully handle missing log sources or permissions.

- Normalized event format and SQLite persistence.

- Transparent, configurable rule-based detections for repeated SSH failures, newly observed listening ports, and suspicious process/resource patterns.

- Incident grouping, severity, risk score, status, evidence links, and event timeline.

- FastAPI read API plus limited incident status update endpoint.

- React/TypeScript dashboard with system overview, events, incidents, process/port views, and event/incident details.

- Safe test generator or documented test procedure that creates synthetic/test events without attacking other systems.

- Automated unit/integration tests for core detection and API behavior.

- Install/run guide, architecture diagrams, security notes, troubleshooting, and demo instructions.

## Should-have, only after core MVP works

- Live updates via polling; WebSockets are not required.

- Export incident report as JSON or CSV.

- Configurable thresholds in a validated YAML or TOML file.

- Optional notification adapter that is disabled by default.

- Optional isolated SSH honeypot in a lab-only profile, added only after the core platform is stable.

## Explicitly out of scope for MVP

- Public-facing deployment, cloud control plane, multi-device fleet management, or remote administration.

- Machine learning or claims of AI-powered threat detection.

- Automatic firewall blocking, killing processes, disabling accounts, or other disruptive remediation.

- Capturing, storing, or displaying real passwords, tokens, or secrets.

- Scanning networks or systems without explicit authorization.

- A production-grade SIEM, endpoint detection and response (EDR), or guarantee of detecting compromise.

| **SCOPE RULE** If a feature is not in Must-have MVP, Claude must not implement it without asking first. Keep the first version small, testable, and reliable. |
|---------------------------------------------------------------------------------------------------------------------------------------------------------------|

# 3. Hardware and environment

| **Item**     | **Requirement / guidance**                                                                                |
|--------------|-----------------------------------------------------------------------------------------------------------|
| Raspberry Pi | Pi 4, preferably 4 GB RAM or more; 64-bit OS.                                                             |
| Storage      | Reliable microSD (32 GB minimum suggested) or USB SSD; avoid writing high-volume telemetry continuously.  |
| Network      | Trusted home/lab LAN. Do not port-forward the dashboard or SSH to the public internet.                    |
| OS           | Raspberry Pi OS Lite 64-bit is preferred for a headless appliance; Desktop is acceptable for development. |
| Access       | SSH from a trusted machine; keep a local recovery route.                                                  |
| Power        | Stable power supply; monitor temperature and throttling during tests.                                     |
| Development  | Can develop on another computer, but test compatibility on the Pi early and often.                        |

## Initial setup checklist

- Flash and update Raspberry Pi OS; enable SSH only for trusted LAN access.

- Create a non-default user with a strong password; use SSH keys where practical.

- Record OS version, architecture, Python version, RAM, storage, and Pi model for the README.

- Set hostname and time zone; confirm system time is synchronized.

- Create a project directory and Python virtual environment.

- Confirm the Pi can reach package repositories; do not expose services publicly.

- Create a Git repository and commit the empty project scaffold.

# 4. Technology decisions

| **Layer**        | **Technology**                                     | **Use / notes**                                                       |
|------------------|----------------------------------------------------|-----------------------------------------------------------------------|
| Operating system | Raspberry Pi OS Lite 64-bit                        | ARM64 Linux host; native host telemetry.                              |
| Runtime          | Python 3.11+ if supported by OS                    | Use the OS-supported Python; pin dependencies.                        |
| Telemetry        | psutil + /proc + standard Linux tools              | Prefer Python libraries; wrap commands safely when needed.            |
| Log source       | systemd journal / auth log adapter                 | Implement adapters; detect which source exists; document permissions. |
| Detection        | Python rule engine                                 | Deterministic, testable rules; no ML in MVP.                          |
| Database         | SQLite                                             | Local single-node persistence; schema migrations required.            |
| Backend          | FastAPI + Pydantic                                 | Typed REST API and OpenAPI docs.                                      |
| Frontend         | React + TypeScript + Vite                          | Responsive local dashboard.                                           |
| Styling          | Tailwind CSS or CSS modules                        | Choose one; avoid mixing styling systems.                             |
| Charts           | Recharts or lightweight SVG charts                 | Keep charts readable and performant.                                  |
| Testing          | pytest; FastAPI TestClient; frontend test tooling  | Unit tests first; add integration tests.                              |
| Packaging        | venv + systemd service; optional Docker for UI/API | Do not let containers obscure host processes/logs.                    |
| Version control  | Git + GitHub                                       | Small commits; issues/checklist; no secrets in repo.                  |

## Technology guardrails

- Confirm every dependency supports ARM64 and the Pi OS version before adding it.

- Keep backend and frontend dependencies pinned or constrained in lock/requirements files.

- Prefer standard library or mature packages over custom low-level collectors.

- Do not run the web application as root. If privileged collection is needed, isolate the minimum privileged helper and document why.

- Use Docker only when it improves reproducibility; native host collection is the default for the MVP.

# 5. System architecture

The MVP uses a modular monolith: one Python application can host collection scheduling, event normalization, detection, incident correlation, database access, and FastAPI routes. Keep modules separated so components can be split later if justified.

┌──────────────────────────── Raspberry Pi 4 ────────────────────────────┐

│ Raspberry Pi OS / Linux │

│ │

│ ┌─────────────────┐ ┌─────────────────┐ ┌──────────────────────┐ │

│ │ System Metrics │ │ Process/Port │ │ Auth/System Log │ │

│ │ psutil, /proc │ │ Inventory │ │ Adapter │ │

│ └────────┬────────┘ └────────┬────────┘ └──────────┬───────────┘ │

│ └────────────────────┼───────────────────────┘ │

│ ▼ │

│ ┌────────────────────┐ │

│ │ Normalized Events │ │

│ └─────────┬──────────┘ │

│ ▼ │

│ ┌────────────────────┐ │

│ │ Rule Detection │ │

│ │ + Risk Scoring │ │

│ └─────────┬──────────┘ │

│ ▼ │

│ ┌────────────────────┐ │

│ │ Incident Correlator│ │

│ └─────────┬──────────┘ │

│ ▼ │

│ ┌────────────────────┐ │

│ │ SQLite │ │

│ └─────────┬──────────┘ │

│ ▼ │

│ ┌────────────────────┐ │

│ │ FastAPI REST API │ │

│ └─────────┬──────────┘ │

└───────────────────────────────┼────────────────────────────────────────┘

▼

┌────────────────────┐

│ React + TypeScript │

│ Local Web Dashboard│

└────────────────────┘

## Data flow

1\. Collector samples host metrics or reads a supported log source.

2\. Adapter converts source data into a common Event object.

3\. Event is validated, timestamped, and persisted.

4\. Detection rules evaluate the event and recent event window.

5\. Matches create/update an Incident and attach evidence event IDs.

6\. API returns metrics, events, incidents, and inventory.

7\. Dashboard polls the API and renders status, tables, timelines, and filters.

8\. User reviews the incident and changes its status to acknowledged/resolved.

## Module boundaries

| **Module**    | **Responsibility**                            | **Must not do**                         |
|---------------|-----------------------------------------------|-----------------------------------------|
| collectors    | Read metrics, logs, process/port snapshots    | Make response decisions                 |
| normalization | Convert raw input to validated event schema   | Execute shell commands from log content |
| detection     | Evaluate rules and emit findings              | Modify host firewall/processes          |
| incidents     | Group findings and maintain lifecycle         | Invent evidence                         |
| storage       | CRUD, migrations, retention                   | Expose DB directly to browser           |
| api           | Validate requests and serialize responses     | Trust arbitrary client input            |
| frontend      | Display/filter data and submit status changes | Contain secrets or privileged logic     |

# 6. Data model and event schema

Use UTC ISO-8601 timestamps internally and in API responses. Store structured event metadata as JSON, but never place secrets or raw credentials in it. Use database migrations even for SQLite.

## Core tables

| **Table**         | **Key fields**                                                                                                       | **Notes**                                                                           |
|-------------------|----------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------|
| events            | id, timestamp, source, event_type, severity, summary, source_ip, username, process_name, metadata_json, incident_id  | Append-oriented evidence. Nullable fields are expected.                             |
| incidents         | id, title, description, severity, risk_score, status, first_seen, last_seen, created_at, updated_at, resolution_note | Status: open, acknowledged, resolved, false_positive.                               |
| system_metrics    | id, timestamp, cpu_percent, memory_percent, disk_percent, temperature_c, uptime_seconds, net_rx_bytes, net_tx_bytes  | Sample on a configurable interval; avoid excessive frequency.                       |
| process_snapshots | id, timestamp, pid, name, username, cpu_percent, memory_percent, command_redacted                                    | Do not collect full command-line arguments by default; they can contain secrets.    |
| listening_ports   | id, observed_at, protocol, local_address, port, process_name, pid                                                    | Store snapshots; compare against a baseline.                                        |
| detection_rules   | id, name, enabled, severity, threshold_json, description                                                             | MVP can begin with code-defined rules; UI editing is future.                        |
| incident_events   | incident_id, event_id                                                                                                | Many-to-many evidence association; use if one event can support multiple incidents. |

## Normalized event contract

Event {

id: UUID

timestamp: UTC ISO-8601

source: "auth_log" \| "system_metrics" \| "process_inventory" \| "port_inventory" \| "test"

event_type: string

severity: "info" \| "low" \| "medium" \| "high" \| "critical"

summary: short human-readable description

source_ip: optional string

username: optional string

process_name: optional string

host: hostname

metadata: object with validated, non-secret fields

}

## Retention and privacy

- Set a configurable retention window (initial default: 14 days) and a maximum database size target.

- Prune old high-volume metrics more aggressively than incidents; never delete unresolved incident evidence without an explicit policy.

- Redact secrets and sensitive command-line arguments before persistence.

- Do not store passwords, password hashes, tokens, private keys, or session cookies.

- Document exactly what is collected, where it is stored, and how to delete it.

# 7. Detection rules and incident logic

MVP detections must be explainable, deterministic, and covered by tests. Detection is a learning tool, not a guarantee that the host is secure.

| **Rule ID** | **Rule**                     | **MVP trigger**                                                                                 | **Default severity** | **Response**                                                   |
|-------------|------------------------------|-------------------------------------------------------------------------------------------------|----------------------|----------------------------------------------------------------|
| SP-001      | Repeated SSH failures        | At least 5 failed SSH authentication events from one source IP within 5 minutes.                | High                 | Create/update incident; attach matching events.                |
| SP-002      | New listening port           | A listening port/protocol is absent from the saved baseline and appears in a later snapshot.    | Medium               | Create event; incident only if policy says so.                 |
| SP-003      | Resource anomaly             | CPU remains above configurable threshold for a sustained window, e.g. 90% for 5 minutes.        | Low/Medium           | Create event; avoid repeated alert spam.                       |
| SP-004      | Unexpected process           | Process name matches a configurable watchlist or a process appears in a user-created test rule. | Medium               | Create event; include process metadata with command redaction. |
| SP-005      | Repeated suspicious activity | Multiple different detection types from same host/source within a correlation window.           | High                 | Group related events into one incident.                        |

## Risk score

Use a transparent 0–100 score. Start with fixed rule weights and cap the total at 100. The score is a prioritization aid, not a probability.

| **Signal**                                     | **Illustrative points** |
|------------------------------------------------|-------------------------|
| Repeated SSH failures                          | +35                     |
| New listening port                             | +20                     |
| Unexpected process                             | +30                     |
| Sustained resource anomaly                     | +10                     |
| Independent rule match in same incident window | +10                     |

Suggested display bands: 0–24 Low, 25–49 Medium, 50–74 High, 75–100 Critical. Make thresholds configurable and document that these values are heuristic.

## Incident lifecycle

OPEN → ACKNOWLEDGED → RESOLVED

└───────────────→ FALSE_POSITIVE

Rules:

\- A new detection creates an incident or attaches to a matching open incident.

\- Correlation keys may include rule ID, source IP, host, and a bounded time window.

\- Update last_seen and risk score when new evidence is attached.

\- Preserve the event timeline and rule explanation.

\- User status changes must be audited with timestamp and optional resolution note.

## Anti-noise requirements

- Use cooldowns or deduplication keys so one persistent condition does not create hundreds of incidents.

- Make time windows and thresholds configurable.

- Show the rule name, exact trigger, and supporting evidence for each detection.

- Do not label an event as confirmed compromise; use careful language such as “possible” or “suspicious”.

# 8. Security, safety, and threat model

## Threat model

| **Asset**           | **Threat**                                 | **MVP mitigation**                                                                      |
|---------------------|--------------------------------------------|-----------------------------------------------------------------------------------------|
| Dashboard/API       | Unauthorized LAN access or exposed service | Bind to localhost by default; document trusted-LAN binding as an opt-in.                |
| Collected telemetry | Sensitive data exposure                    | Minimize collection, redact secrets, local storage, access controls where needed.       |
| Pi host             | Collector/API compromise                   | Least privilege, non-root service, dependency pinning, input validation.                |
| Database            | Tampering, disk exhaustion                 | File permissions, retention, backups, size limits.                                      |
| SSH access          | Accidental lockout                         | No automatic firewall or SSH changes; preserve recovery path.                           |
| Honeypot (optional) | Abuse or lateral movement                  | Isolated lab-only profile, no public exposure, no outbound access, no real credentials. |

## Non-negotiable safety requirements

- Default network binding is 127.0.0.1. Any LAN binding requires an explicit configuration step and warning.

- Never expose the dashboard, API, or honeypot to the public internet as part of the project instructions.

- Do not implement automatic blocking, process killing, account disabling, or firewall edits in the MVP.

- All tests must target the local lab/Pi or synthetic fixtures; do not scan third-party systems.

- Do not execute commands or shell fragments derived from logs, usernames, process names, or API input.

- Avoid storing raw command lines by default; redact arguments and secrets.

- Use a non-root service account; document any narrowly scoped permission exceptions.

- Validate and bound API query parameters, request bodies, log input sizes, and retention settings.

- Keep secrets out of Git; provide .env.example with placeholder values only.

- Add an uninstall and recovery procedure.

## Optional honeypot policy

The honeypot is not required for the MVP. If added later, use a mature project such as Cowrie only in an isolated lab profile, with explicit user opt-in, no real credentials, no public port forwarding, restricted egress, and clear legal/ethical scope. Store only necessary session metadata; never use it to collect credentials from real users. The initial MVP should detect the Pi’s own authentication events instead.

# 9. API contract

Prefix all routes with /api/v1. Return consistent JSON, UTC timestamps, pagination for lists, and structured error responses. Generate and use FastAPI’s OpenAPI docs during development.

| **Method + route**            | **Purpose**                    | **Query/body notes**                                         |
|-------------------------------|--------------------------------|--------------------------------------------------------------|
| GET /health                   | Liveness/readiness check       | No sensitive host detail.                                    |
| GET /api/v1/system/status     | Current host summary           | CPU, memory, disk, uptime, temperature if available.         |
| GET /api/v1/system/metrics    | Historical metric series       | from, to, interval, bounded result count.                    |
| GET /api/v1/events            | Paginated event list           | limit, cursor/offset, severity, type, time range, source IP. |
| GET /api/v1/events/{id}       | Event detail                   | Return redacted metadata.                                    |
| GET /api/v1/incidents         | Incident list                  | status, severity, limit, time range.                         |
| GET /api/v1/incidents/{id}    | Incident detail                | Include evidence events and timeline.                        |
| PATCH /api/v1/incidents/{id}  | Update incident status         | Allow-listed status + optional resolution note.              |
| GET /api/v1/processes         | Latest process snapshot        | Bounded, redacted fields.                                    |
| GET /api/v1/network/listeners | Latest listening-port snapshot | Protocol, local address, port, process if available.         |
| GET /api/v1/rules             | List active detection rules    | Rule descriptions and thresholds; read-only in MVP.          |

## API conventions

- Use Pydantic response/request models; do not return raw ORM objects.

- List endpoints return {items, total, limit, next_cursor} or a consistent equivalent.

- Use 400 for invalid input, 404 for missing records, 422 for validation errors, and 500 only for unexpected failures.

- Never return environment variables, secrets, absolute sensitive paths, or unredacted raw logs.

- Add tests for pagination limits, filters, invalid status changes, and missing IDs.

# 10. Dashboard requirements

| **Page**       | **Required content and interactions**                                                                                           |
|----------------|---------------------------------------------------------------------------------------------------------------------------------|
| Overview       | CPU/RAM/disk cards, uptime, recent events, open incident count, severity summary, small metric charts.                          |
| Events         | Paginated table; filter by time, severity, type, source; search summary/source IP; event detail panel.                          |
| Incidents      | Open/acknowledged/resolved tabs; severity and risk score; incident details, evidence timeline, rule explanation; status update. |
| System         | Current metrics, historical charts, temperature/throttling where available, collection status.                                  |
| Processes      | Latest process inventory; PID/name/user/CPU/memory; clear note that process metadata may be incomplete.                         |
| Network        | Listening ports and protocol; highlight newly observed ports; show local address and associated process if known.               |
| Settings/About | Version, collector status, data retention setting or documentation link, privacy/collection notice.                             |

## UI principles

- Use a clear dark or neutral security-console aesthetic, but prioritize readability and accessibility.

- Display timestamps with local-time presentation while preserving UTC in data.

- Use explicit empty, loading, stale-data, and error states.

- Do not rely on color alone for severity; include text labels and icons.

- Make the UI usable at common laptop widths and on a phone-sized viewport.

- Poll at a reasonable interval (e.g. 5–10 seconds for overview); avoid unnecessary high-frequency requests.

# 11. Proposed repository structure

sentinelpi/

├── README.md

├── LICENSE

├── .gitignore

├── .env.example

├── pyproject.toml \# or requirements + dev requirements

├── backend/

│ ├── app/

│ │ ├── main.py

│ │ ├── config.py

│ │ ├── api/

│ │ │ ├── routes_system.py

│ │ │ ├── routes_events.py

│ │ │ ├── routes_incidents.py

│ │ │ ├── routes_inventory.py

│ │ │ └── schemas.py

│ │ ├── collectors/

│ │ │ ├── metrics.py

│ │ │ ├── processes.py

│ │ │ ├── listeners.py

│ │ │ └── auth_logs.py

│ │ ├── detection/

│ │ │ ├── engine.py

│ │ │ ├── rules.py

│ │ │ └── scoring.py

│ │ ├── incidents/

│ │ │ └── correlator.py

│ │ ├── models/

│ │ │ └── events.py

│ │ ├── storage/

│ │ │ ├── database.py

│ │ │ ├── repositories.py

│ │ │ └── migrations/

│ │ └── tests/

│ └── systemd/

│ └── sentinelpi.service

├── frontend/

│ ├── src/

│ │ ├── api/

│ │ ├── components/

│ │ ├── pages/

│ │ ├── types/

│ │ └── utils/

│ └── package.json

├── scripts/

│ ├── install_dev.sh

│ ├── run_local.sh

│ └── generate_test_events.py

├── docs/

│ ├── architecture.md

│ ├── threat-model.md

│ ├── testing.md

│ ├── troubleshooting.md

│ └── demo-script.md

└── assets/

└── diagrams/

Claude may adjust this structure if it explains why first. Keep the repo understandable; do not create empty abstractions for hypothetical future features.

# 12. Step-by-step implementation roadmap

Claude must complete one phase at a time. At each gate, it should summarize files changed, commands run, test results, known limitations, and the exact next step. Do not proceed if the gate fails.

## Phase 0 — Confirm environment and decisions

- Ask whether development is on the Pi or another computer; record OS/architecture and available RAM/storage.

- Check package and ARM64 compatibility for proposed dependencies.

- Confirm local-only network posture, repository name, and preferred styling option.

- Create a concise implementation plan and assumptions list.

| **PHASE GATE** Approved environment notes and frozen MVP decisions; no code beyond a minimal scaffold. |
|--------------------------------------------------------------------------------------------------------|

## Phase 1 — Repository scaffold and developer workflow

- Create the repository structure, Python environment, frontend scaffold, .gitignore, .env.example, and basic README.

- Add formatter/linter and test commands; create a health endpoint and simple frontend shell.

- Add a version and configuration loader.

| **PHASE GATE** Backend starts, frontend builds, health endpoint passes, clean initial commit. |
|-----------------------------------------------------------------------------------------------|

## Phase 2 — Host telemetry

- Implement metrics collector for CPU, memory, disk, uptime, network counters, and optional temperature.

- Implement process and listening-port snapshots with safe, bounded collection.

- Add collector status and error handling for unavailable permissions/features.

| **PHASE GATE** Unit tests pass using mocks; live telemetry works on the Pi; no root-only assumption. |
|------------------------------------------------------------------------------------------------------|

## Phase 3 — Database and event pipeline

- Create schema and migration strategy.

- Implement normalized event model, repository layer, UTC timestamps, retention job, and safe serialization.

- Add synthetic event generator for repeatable tests.

| **PHASE GATE** Events and metrics persist and can be retrieved; schema tests and retention tests pass. |
|--------------------------------------------------------------------------------------------------------|

## Phase 4 — Authentication log adapter

- Detect available log source (systemd journal or supported auth log).

- Parse only relevant authentication outcomes; tolerate format differences and malformed lines.

- Redact sensitive fields and handle permission denial clearly.

| **PHASE GATE** Fixture tests cover supported formats; live test events appear when the host produces them. |
|------------------------------------------------------------------------------------------------------------|

## Phase 5 — Detection engine

- Implement SP-001 through SP-004 as independent, testable rules.

- Add time-window queries, deduplication/cooldowns, rule explanations, and risk scoring.

- Keep thresholds in validated configuration.

| **PHASE GATE** Tests prove trigger and non-trigger cases; duplicate alert spam is controlled. |
|-----------------------------------------------------------------------------------------------|

## Phase 6 — Incident correlation and lifecycle

- Create/update incidents and attach supporting event IDs.

- Implement status transitions, audit timestamps, resolution notes, and timeline retrieval.

- Document correlation keys and limitations.

| **PHASE GATE** Integration tests verify grouping, score updates, status transitions, and evidence preservation. |
|-----------------------------------------------------------------------------------------------------------------|

## Phase 7 — FastAPI endpoints

- Implement versioned routes, response models, pagination, filtering, and validation.

- Add error handling, API docs, and local-only default binding.

- Add endpoint tests.

| **PHASE GATE** All documented endpoints work; invalid inputs are rejected; API tests pass. |
|--------------------------------------------------------------------------------------------|

## Phase 8 — Frontend dashboard

- Build navigation, overview cards/charts, events table, incident views, system, process, and network pages.

- Implement loading/error/empty/stale states and filters.

- Connect typed API client; avoid hard-coded demo data in production mode.

| **PHASE GATE** Frontend builds; pages use real API data; basic responsive/accessibility review passes. |
|--------------------------------------------------------------------------------------------------------|

## Phase 9 — End-to-end verification

- Run the whole stack on the Pi.

- Generate controlled test events and verify collector → event → detection → incident → UI.

- Measure CPU, RAM, disk writes, API latency, and dashboard refresh behavior.

| **PHASE GATE** A repeatable demo passes end-to-end; performance figures are recorded honestly. |
|------------------------------------------------------------------------------------------------|

## Phase 10 — Packaging and operational hardening

- Add a systemd service and least-privilege setup; document optional Docker boundaries.

- Set file permissions, retention, backup/restore, upgrade, and uninstall procedures.

- Check binding configuration and firewall assumptions without automatically changing them.

| **PHASE GATE** Fresh install and uninstall are reproducible; no service runs as root by default. |
|--------------------------------------------------------------------------------------------------|

## Phase 11 — Documentation and portfolio polish

- Write complete README, architecture/data-flow diagrams, threat model, known limitations, and demo script.

- Capture real screenshots and record a short demo.

- Add tests/coverage summary and measured hardware performance.

| **PHASE GATE** A new reader can understand, install, run, test, and demo the project from the repository. |
|-----------------------------------------------------------------------------------------------------------|

# 13. Testing and acceptance criteria

| **Area**     | **Acceptance test**                                                                                    |
|--------------|--------------------------------------------------------------------------------------------------------|
| Installation | Documented install works on a clean supported Pi OS image; commands are copyable and complete.         |
| Metrics      | Metrics return valid bounded values; unavailable temperature/permissions produce a clear status.       |
| Events       | Malformed log entries are ignored safely; valid fixtures normalize consistently.                       |
| Detection    | Each rule has positive, negative, boundary, and time-window tests.                                     |
| Correlation  | Repeated matches deduplicate; evidence events remain linked; risk score is capped at 100.              |
| API          | Pagination/filter validation works; invalid status transitions and missing IDs return expected errors. |
| Frontend     | All required pages load; empty/error/stale states work; no fake production data.                       |
| Security     | Default bind is localhost; no secrets committed; no destructive response code; inputs bounded.         |
| Performance  | Record idle and typical-load CPU/RAM, database growth over a test interval, and API response time.     |
| Recovery     | Backup/restore and uninstall instructions are tested.                                                  |

## Test data strategy

- Use fixture log lines and synthetic events for deterministic tests.

- Use a dedicated local test account or safe, controlled authentication failures only when needed.

- Never test against third-party IPs or systems.

- Keep test event generation behind an explicit development/test command.

# 14. Performance and quality targets

These are initial engineering targets, not claims. Claude should measure actual results on the target Pi and report deviations rather than fabricate numbers.

| **Metric**          | **Initial target / method**                                                  |
|---------------------|------------------------------------------------------------------------------|
| Idle resource use   | Aim for modest CPU/RAM use; measure after warm-up and report actual values.  |
| Metric collection   | Default interval around 10 seconds; configurable and bounded.                |
| Dashboard freshness | Overview refresh roughly every 5–10 seconds; show last update time.          |
| API latency         | Measure local p50/p95 for common list/status routes under test load.         |
| Storage             | Retention and DB size limits prevent unbounded growth.                       |
| Reliability         | Collector errors should not crash API; log failures and continue where safe. |

# 15. README and demo deliverables

## README must include

- Project summary and goals; explicit statement that this is a learning/portfolio project.

- Feature list and MVP/non-goals.

- Hardware/OS tested and software requirements.

- Architecture and data-flow diagrams.

- Installation, configuration, run, test, upgrade, backup, and uninstall instructions.

- Dashboard screenshots and a short demo video/GIF link.

- Example detection walkthrough with synthetic/local test events.

- Security/privacy notes, data collected, retention, default binding, and safe-use warning.

- Performance measurements with hardware/OS context.

- Known limitations and future roadmap.

- Credits and licenses for third-party dependencies.

## Demo script (3–5 minutes)

1.  Show the Pi, OS/architecture, and local dashboard.

2.  Show current system health and the collector’s last update.

3.  Generate a safe synthetic repeated-SSH-failure event sequence.

4.  Show the detection explanation and created incident.

5.  Open incident evidence timeline; acknowledge and resolve it with a note.

6.  Show the event filters and system/network inventory.

7.  End with architecture, tests, measured resource use, and known limitations.

# 16. Git and Claude collaboration workflow

8.  Keep this document in the repository as docs/MASTER_PROJECT_SPEC.md.

9.  Work on a feature branch per phase or coherent feature; use small commits.

10. Before code changes, Claude should inspect existing files and summarize the plan.

11. Claude must not overwrite working files wholesale without explaining the change.

12. After each implementation batch, run relevant tests/lint/build and report exact commands and results.

13. Review diffs yourself. Do not paste secrets, private keys, or personal logs into Claude.

14. Commit only after tests pass and you understand the changes.

15. If an assumption affects security, data collection, privileges, or networking, Claude must ask before proceeding.

# 17. Copy-paste master prompt for Claude

| **START HERE** Attach this document to Claude or paste its contents into the project context. Then use the prompt below. Claude should begin with Phase 0 and not jump ahead. |
|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|

You are my senior software engineering mentor and implementation partner for SentinelPi. Use the attached SentinelPi Master Project Outline as the source of truth.

Your job is to help me build the project step by step from initial setup through a tested, documented portfolio release. Do not attempt to generate the entire application at once.

Working rules:

1\. Start with Phase 0 only. Ask me for any missing environment details that materially affect implementation (Pi model/RAM, OS/architecture, where I am developing, and whether the repo exists). Do not ask questions already answered in the document.

2\. Before each phase, summarize its goal, files to create/change, key decisions, and test plan.

3\. Implement in small, reviewable batches. Explain important code and Linux/security concepts so I learn, not just copy.

4\. Follow the MVP scope and safety requirements. Do not add out-of-scope features without asking.

5\. Default to local-only access, least privilege, no destructive response actions, no public exposure, no credential collection, and no secrets in Git.

6\. Verify ARM64 and Raspberry Pi OS compatibility. Do not assume x86 hardware.

7\. Keep host telemetry collection separate from API/UI code. Do not run the web service as root.

8\. For every phase, provide exact commands, expected output, tests, and troubleshooting steps.

9\. Run or help me run tests before declaring a phase complete. Never claim tests passed unless they were actually run and their output was observed.

10\. At the end of each phase, report: files changed, commands run, test results, known limitations, security considerations, and the next phase.

11\. Stop at the phase gate and wait for my approval before proceeding.

12\. If you need to make a material architecture/security decision not settled by the spec, explain the options and ask me.

Begin with Phase 0. First inspect the project context and ask only the minimum necessary questions. Then give me a concise environment verification checklist.

# 18. Decisions Claude must not silently make

- Changing the MVP scope or adding ML.

- Binding the API/dashboard to a non-local interface.

- Adding a honeypot or exposing any honeypot port.

- Collecting raw command lines, credentials, or additional sensitive telemetry.

- Running the backend/collector as root or granting broad sudo permissions.

- Adding automatic firewall, process, account, or service changes.

- Switching the database or introducing multiple services/microservices.

- Adding paid APIs, cloud dependencies, or third-party telemetry upload.

- Changing data retention or deleting unresolved incident evidence.

# 19. Short glossary

| **Term**        | **Meaning in SentinelPi**                                                  |
|-----------------|----------------------------------------------------------------------------|
| Telemetry       | Measurements or observations collected from the Pi.                        |
| Event           | One normalized observation, such as a failed SSH login or new port.        |
| Detection rule  | A testable condition that matches one or more events.                      |
| Incident        | A grouped investigation record containing related detections and evidence. |
| Correlation     | Connecting events that share a source, time window, host, or other key.    |
| Risk score      | A heuristic priority number; not a probability.                            |
| Baseline        | A known initial set of listening ports or other expected state.            |
| Least privilege | Give each component only the permissions it needs.                         |
| ARM64           | 64-bit ARM architecture used by supported Raspberry Pi OS images.          |

# 20. Final release checklist

- [ ] All Must-have MVP features implemented and tested.

- [ ] Project installs and runs on the target Raspberry Pi 4.

- [ ] No secrets or real credentials in the repository or demo.

- [ ] Dashboard/API default to local-only access.

- [ ] Detection rules have documented thresholds and tests.

- [ ] Incident evidence and status lifecycle work end to end.

- [ ] Performance measurements are real and contextualized.

- [ ] README, architecture diagram, threat model, troubleshooting, and demo script are complete.

- [ ] Screenshots/video show the real implementation, not mockups.

- [ ] Known limitations and future ideas are clearly separated from completed features.

- [ ] Fresh-install, backup/restore, and uninstall instructions have been verified.

| **PROJECT NORTH STAR** A modest system that works reliably, explains its detections, protects the host, and is easy to reproduce is more valuable than a large feature list that is untested or unsafe. |
|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
