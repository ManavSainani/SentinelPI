# SentinelPi

A local-first host monitoring and security-awareness dashboard. Full design in
[`docs/MASTER_PROJECT_SPEC.md`](docs/MASTER_PROJECT_SPEC.md).

**Status:** Phase 1 (scaffold). Health endpoint and dashboard shell only.

## Requirements
- Python 3.11+ (tested on 3.12 macOS, 3.13 Pi OS)
- Node 20+ (only needed on the machine that builds the frontend)

## Quick start (macOS or Pi)
```bash
make setup
make test && make lint
make run          # builds UI, serves on http://127.0.0.1:8787
```

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
