# Testing

```bash
make test    # backend (pytest) then frontend (vitest)
make lint    # ruff, eslint, tsc
```

## What is covered
| Suite | Tests | Notes |
|---|---|---|
| Backend (pytest) | 452 | Collectors, parsers, each detection rule (positive, negative, boundary, window), correlation, lifecycle, API, storage, backup/restore, deployment files |
| Frontend (vitest) | 56 | Formatting, status text, kiosk mode logic, polling hook, API client, every page's loading, error, empty and stale states |
| End-to-end | 18 checks | `python -m sentinelpi.verify demo` runs the real monitor and API against a fake auth log |

Backend line coverage was **90 %** (3,433 statements) when measured with
`pytest --cov=sentinelpi` on 2026-11-08. The lowest modules are the demo tool itself
(`verify.py`, exercised by the demo rather than unit tests) and the telemetry CLI.

To reproduce: `pip install pytest-cov` then `cd backend && python -m pytest --cov=sentinelpi`.
`pytest-cov` is not a project dependency.

## Test data
All attack data is synthetic: documentation-range IPs (RFC 5737, `203.0.113.0/24`) in a
temporary log file, and a harmless copy of `sleep` named `nc`. Nothing is ever aimed at another
system. Timezone-sensitive tests run under several `TZ` values.

## Real-world checks done on the Pi
- Phase 6: a real failed-SSH attack from the Mac became an incident; acknowledge, resolve and the audit trail worked.
- Phase 8: the same attack took over the kiosk screen.
- Phase 9: demo 18/18 and the idle benchmark ([PERFORMANCE.md](PERFORMANCE.md)).
- Phase 10: services start at boot and the kiosk comes up unattended.

## Recovery
`python -m sentinelpi.storage backup/restore` is covered by tests for the round trip, refusing
to overwrite, garbage or foreign files, newer schemas, and a missing database. See
[DEPLOYMENT.md](DEPLOYMENT.md#backup-restore-and-uninstall).
