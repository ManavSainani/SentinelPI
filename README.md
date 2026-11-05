# SentinelPi

A local-first host monitoring and security-awareness dashboard. Full design in
[`docs/MASTER_PROJECT_SPEC.md`](docs/MASTER_PROJECT_SPEC.md).

**Status:** Phase 5 (detection engine and monitoring loop). The system now collects, stores and detects; incidents (Phase 6), the API (Phase 7) and the dashboard (Phase 8) are next.

## Requirements
- Python 3.11+ (tested on 3.12 macOS, 3.13 Pi OS)
- Node 20+ (only needed on the machine that builds the frontend)

## Quick start (macOS or Pi)
```bash
make setup
make test && make lint
make run          # builds UI, serves on http://127.0.0.1:8787
```

## Live telemetry check (no API or database needed)
```bash
.venv/bin/python -m sentinelpi.collectors            # everything
.venv/bin/python -m sentinelpi.collectors metrics    # or: processes | ports
```
Each collector reports a status (`ok`, `degraded`, `unavailable`, `error`) plus any optional
fields it could not provide. What differs by host:

| | Raspberry Pi (Linux) | macOS |
|---|---|---|
| CPU / memory / disk / uptime / network | yes | yes |
| Temperature | yes (sysfs / psutil) | not available |
| Processes | yes (own + others, name only) | yes |
| Listening ports | yes; process shown only for your own sockets | via `lsof` fallback: TCP only, your own processes (`degraded`) |

Privacy: process command lines, environment and working directories are never read.

## Storage (SQLite)
```bash
.venv/bin/python -m sentinelpi.storage migrate        # create/upgrade the schema
.venv/bin/python -m sentinelpi.storage collect-once   # store one metrics/process/port snapshot
.venv/bin/python -m sentinelpi.storage seed-events 40 # synthetic events, source="test"
.venv/bin/python -m sentinelpi.storage status         # row counts and size
.venv/bin/python -m sentinelpi.storage prune          # run retention now
```
Run from the repo root: the default database is `data/sentinelpi.db` (git-ignored, owner-only
permissions). Set `db_path` in the config for a fixed location.

**What is stored:** events (auth/system/test, sanitized), CPU/memory/disk/temperature/network
counters, the top-50 processes (name, user, CPU, memory; never command lines), and listening
ports. Secret-looking values are redacted before saving (best effort). Metadata keys containing
words like `password` or `token` always have their value replaced, so name counters
`failure_count`, not `password_failures`.

**Retention (defaults, see `config/sentinelpi.example.toml`):** events 14 days, metrics 7,
process/port snapshots 3, resolved incidents 90, size target 256 MB. Open or acknowledged
incidents and their evidence are never auto-deleted.

**To delete everything:** stop the service and remove `data/sentinelpi.db*`.

**Schema changes:** never edit an applied migration (it is checksummed); add the next
`NNNN_name.sql` in `backend/src/sentinelpi/storage/migration_files/`.

## SSH authentication events (Phase 4)
```bash
.venv/bin/python -m sentinelpi.collectors auth      # dry run: print parsed events, store nothing
.venv/bin/python -m sentinelpi.storage poll-auth    # read new events and store them (+ cursor)
```
**Sources, in order:** the systemd journal (`journalctl`, only the `ssh.service`/`sshd.service`
units), then `/var/log/auth.log` or `/var/log/secure`. The first readable one is used, and the
status says which and why others were skipped. macOS has neither, so it reports `unavailable`.

**Permissions:** reading the journal needs membership in the `adm` or `systemd-journal` group
(check with `groups`). Reading it grants access to *all* system logs, not just SSH, so the
packaged service will run as a dedicated non-root user with only that group. Without access the
status tells you exactly this instead of silently returning nothing.

**Captured:** failed logins, probes with unknown usernames, and successful logins. Everything
else (disconnects, PAM duplicates, `Failed none` scanner noise) is ignored on purpose.

**Privacy:** the attempted username is stored only if it is a real local account. Failed
logins often contain typos or passwords typed into the username field, so for unknown users
no name is stored or shown. Key fingerprints are dropped.

**Trust and limits:**
- Journal entries are accepted only if journald itself tagged them as coming from the ssh unit,
  so a local user cannot forge SSH events with `logger`. Plain log files have no such
  guarantee; prefer the journal.
- One bad attempt can produce both an `auth.ssh_invalid_user` and an `auth.ssh_failed_login`
  event. Both carry `src_port` so detection can count each connection once.
- Event IDs are derived from the log entry, so re-reading a log can never create duplicates.

**Safe live test** (only ever against your own Pi, over loopback or your own LAN):
1. From your Mac: `ssh <user>@<pi-address>`, log in, then exit (creates a successful login).
2. On the Pi: `ssh -o PubkeyAuthentication=no nosuchuser@127.0.0.1`, type a wrong password
   twice, then press Ctrl+C (creates failed-login / unknown-user events).
3. `poll-auth`, then `status`.

## Detection and monitoring (Phase 5)
```bash
.venv/bin/python -m sentinelpi.monitor            # collect, poll logs, detect, prune; Ctrl+C stops
.venv/bin/python -m sentinelpi.monitor --once     # run every job once and print the results
.venv/bin/python -m sentinelpi.detection rules    # the rules and their effective thresholds
.venv/bin/python -m sentinelpi.detection run      # evaluate all rules once, right now
.venv/bin/python -m sentinelpi.detection score SP-001 SP-004   # preview a risk score
```

| Rule | Fires when | Default severity | Cooldown |
|---|---|---|---|
| SP-001 Repeated SSH failures | 5+ failed attempts from one IP within 5 minutes (inclusive) | High | 30 min per IP |
| SP-002 New listening port | a protocol/port is absent from the approved baseline | Medium | 24 h per port |
| SP-003 Sustained high CPU | every sample above 90% for a full 5-minute window | Low (Medium if average >= 98%) | 30 min |
| SP-004 Unexpected process | a running process name is on the watchlist | Medium | 6 h per name |

Every detection is stored as an event (`detection.*`) whose metadata holds the rule name, the
exact trigger, an explanation, the evidence (SSH event IDs, ports, PIDs, CPU stats), the dedupe
key and the risk points. Thresholds live in the `[detection.*]` sections of the config; unknown
keys are rejected so a typo cannot silently leave a default in place.

**Approving the port baseline (SP-002).** The rule stays "skipped" until you approve a baseline:
```bash
.venv/bin/python -m sentinelpi.storage collect-once
.venv/bin/python -m sentinelpi.detection baseline capture    # shows the ports, asks to approve
.venv/bin/python -m sentinelpi.detection baseline show
```
Capture it on a machine you trust, after it has been running normally for a few minutes. Re-run
`capture` after you deliberately add a service.

**How noise is controlled.** One persistent condition produces one alert per cooldown, not one
per evaluation. Rules that lack enough data (stale snapshot, gaps in the CPU samples, no
baseline) report *skipped* with the reason instead of guessing. A failing rule is isolated and
reported by exception type only.

**Limits worth knowing.**
- Detection is a learning tool, not a guarantee. The risk score is a heuristic, not a probability.
- Watchlist matching is by process name only. Command lines are never collected, and a renamed
  binary will not match.
- Linux truncates process names to 15 characters; longer watchlist entries match that prefix.
- One bad SSH attempt can log both an "invalid user" and a "failed login" event; SP-001 counts
  each connection's attempts once.
- SP-002 on macOS sees TCP only; a baseline records which protocols it could see and never
  treats an invisible protocol as new.
- The `ignored_source_ips` allowlist is empty by default because an allowlist is a blind spot.

## Incidents (Phase 6)
The monitor now groups detections into incidents automatically (it runs right after each
detection pass). You can also work with them from the command line:
```bash
.venv/bin/python -m sentinelpi.incidents list [--status open]
.venv/bin/python -m sentinelpi.incidents show <id>       # details, score breakdown, timeline
.venv/bin/python -m sentinelpi.incidents ack <id> [--note "..."]
.venv/bin/python -m sentinelpi.incidents resolve <id> --note "blocked at the router"
.venv/bin/python -m sentinelpi.incidents false-positive <id> --note "my own scan"
.venv/bin/python -m sentinelpi.incidents run             # correlate right now
```
`<id>` is the full id or any unique prefix (the first 8 characters shown by `list`).

**Correlation keys.** A detection joins the *active* (open or acknowledged) incident with the
same **host** and the same **subject** whose activity is within `correlation_window_minutes`
(default 30, inclusive) of it:
- the subject is the **source IP** for detections that have one (SP-001);
- the subject is **host-local** for detections without one (SP-002, SP-003, SP-004).

Otherwise a new incident opens, if the rule is in `open_incident_rules` (default SP-001,
SP-002, SP-004). SP-003 (CPU) only *supports* an existing incident, so a CPU spike on its own
stays a plain event. An incident stops growing after `max_incident_hours` (default 24), so a
long-running condition starts a fresh incident rather than one endless record.

**SP-005, repeated suspicious activity.** When one incident collects `escalate_distinct_rules`
(default 2) different rules, its severity is raised to at least High, the score gains +10 for
each extra rule, and the escalation is written to the audit trail.

**Score and severity.** The risk score is recomputed from the distinct rules attached (the
same rule firing again adds nothing); the breakdown is stored and shown. Severity is the
highest detection severity, raised by SP-005, and never lowered. Severity and the score band
are separate on purpose: a single SSH burst is High severity but a 35 score (Medium band).

**Lifecycle.** `open -> acknowledged -> resolved`, and `open`/`acknowledged -> false_positive`
(or `open -> resolved` directly). Resolved and false-positive are final: if the activity comes
back it opens a new incident, so history is never rewritten. Every change is audited with a
timestamp, actor and optional note, and applied with a compare-and-swap so two writers cannot
both win. Notes are redacted and limited to 500 characters.

**Evidence is preserved.** The correlator only links existing events; it never edits or
invents them. Active incidents and their events are never deleted by retention. Resolved ones
are kept `incident_days` (90) and then removed together with their events and audit trail.

**Limits worth knowing.**
- An SSH incident (from an IP) and a host-local incident on the same host are not merged:
  the detections carry no shared key. A person reading both can see the link by time.
- New evidence on an *acknowledged* incident updates it but does not re-open it.
- The audit actor is `user` or `system`; there is no login yet, so it is not a person's identity.

## API (Phase 7)
Start it (the monitor is a separate process, see above):
```bash
.venv/bin/python -m sentinelpi.main        # http://127.0.0.1:8787 ; interactive docs at /api/docs
```
All routes live under `/api/v1`. Lists return `{items, total, limit, next_cursor}`; pass
`next_cursor` back as `cursor` for the next page (rows are never skipped or repeated while new
ones arrive). Timestamps are UTC ISO-8601; query timestamps must carry a timezone (`...Z`).
Errors always look like `{"error": {"code", "message"}}` and never echo your input.

| Route | Notes |
|---|---|
| `GET /health` | liveness, no host detail |
| `GET /system/status` | one summary for the kiosk: `overall` (ok / warning / alert) with `reasons`, monitor heartbeat, latest metrics and their age, incident counts, `active_alert` (most severe *open* incident), `open_incidents` |
| `GET /system/metrics` | `from`, `to`, `interval_seconds`; never more than 1000 points (averaged into buckets when needed) |
| `GET /events`, `/events/{id}` | filters: `severity` (minimum), `type`, `source`, `source_ip`, `from`, `to`, `limit` (1-200), `cursor` |
| `GET /incidents`, `/incidents/{id}` | filters: `status`, `severity`, `from`, `to`; detail includes score breakdown and timeline |
| `PATCH /incidents/{id}` | body `{"status": "acknowledged" \| "resolved" \| "false_positive", "note": "..."}`; illegal transitions are `409` |
| `GET /processes` | latest snapshot; `sort` = cpu / memory / name; command lines are never returned |
| `GET /network/listeners` | latest snapshot; `protocol`, `exposed_only`; each row says whether it is reachable beyond loopback |
| `GET /rules` | effective rule thresholds, read-only |

**Why `overall` and `active_alert` exist.** The kiosk and, later, the status LEDs should not
have to re-derive "is something wrong". `alert` means an open incident of High severity or
above; `warning` means a lower-severity open incident, a stopped monitor, or stale metrics.
Acknowledging an incident stops it being the active alert. This is a convenience summary, not
a new judgement: it is computed only from the incidents and heartbeat you can already see.

**Protections for a local, login-less API.** A Host-header allowlist (blocks DNS rebinding), a
same-origin check plus JSON-only bodies on the one write endpoint (blocks other web pages from
making your browser change an incident), no CORS, and interactive docs that switch themselves
off if you bind to a non-loopback address. Reach it from your Mac with an SSH tunnel:
`ssh -L 8787:127.0.0.1:8787 msainani@manavpi.local`, then open `http://localhost:8787`.

**Limits worth knowing.**
- There is no login. Anyone who can reach the port can read everything and change incident
  status, which is why it binds to loopback. Exposing it to the network needs authentication
  first (Phase 10).
- `PATCH` records the actor as `user`; it is not an identity.
- The status summary treats a missing heartbeat as "monitor not running", including on a fresh
  install before the monitor has ever started.

## Development (two terminals)
```bash
make dev-backend    # API :8787
make dev-frontend   # UI  :5173 (open this one)
```

## Deploying to the Pi without Node
Build on the Mac (`make build`), then copy `frontend/dist/` to the same path in the
Pi's checkout (e.g. `rsync -av frontend/dist/ pi@manavpi.local:~/SentinelPI/frontend/dist/`).
The backend serves it automatically.

## Security defaults
- Binds to `127.0.0.1` only. Changing it logs a warning (no auth exists yet).
- No automatic blocking or remediation, ever, in the MVP.
- `data/`, `.env`, and `config/sentinelpi.toml` are git-ignored.
