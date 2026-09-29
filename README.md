# SentinelPi

A local-first host monitoring and security-awareness dashboard. Full design in
[`docs/MASTER_PROJECT_SPEC.md`](docs/MASTER_PROJECT_SPEC.md).

**Status:** Phase 4 (SSH authentication log adapter). Events are collected and stored; no detection rules or dashboard data yet.

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
