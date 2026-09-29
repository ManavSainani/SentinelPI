# SentinelPi

A local-first host monitoring and security-awareness dashboard. Full design in
[`docs/MASTER_PROJECT_SPEC.md`](docs/MASTER_PROJECT_SPEC.md).

**Status:** Phase 3 (SQLite storage, event model, retention). Collectors and storage work; no detection or dashboard data yet.

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
