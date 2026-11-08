# Performance on the target host

Measured with `python -m sentinelpi.verify bench --idle-seconds 120` on 2026-11-08, default
intervals (10 s metrics, 60 s snapshots), monitor and API as separate processes, idle host.

| | Value |
|---|---|
| Host | Raspberry Pi 4 Model B (4 GB), Pi OS, Linux 6.12 (rpt-rpi-v8), Python 3.13.5 |
| Monitor | 0.46 % of one core, 38 MB RSS |
| API | 0.23 % of one core, 59 MB RSS |
| Database growth, idle | about 480 KB/hour (about 11 MB/day before retention pruning) |

API latency, 100 sequential local requests per route (p50 / p95):

| Route | p50 | p95 |
|---|---|---|
| `/health` | 3.6 ms | 6.7 ms |
| `/system/status` | 9.2 ms | 9.5 ms |
| `/events?limit=50` | 22.0 ms | 23.6 ms |
| `/incidents?limit=50` | 8.4 ms | 8.6 ms |
| `/system/metrics` | 9.5 ms | 9.8 ms |
| `/network/listeners` | 9.5 ms | 9.7 ms |

Attack to full-screen alert: 5.2 s in the demo, which uses fast intervals for the auth log.

## Caveats
- Idle host only. Numbers will rise during an attack burst or with a large database.
- "Disk written per minute" reported 0.0 for both processes. The kernel counts writes when
  pages are flushed, so a 2-minute window can miss them. The database growth figure is the
  reliable measure of write volume.
- Latency is local loopback, with no browser or SSH tunnel overhead.
