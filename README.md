# SentinelPi

A local-first host monitoring and security-awareness dashboard. Full design in
[`docs/MASTER_PROJECT_SPEC.md`](docs/MASTER_PROJECT_SPEC.md).

**Status:** Phase 2 (host telemetry collectors). Not yet wired to a database or the dashboard.

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
