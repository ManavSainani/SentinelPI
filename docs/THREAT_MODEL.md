# Threat model

SentinelPI is a learning project that watches one Raspberry Pi. This page says what it
defends, what it trusts, and what it does not do.

## Assets
1. The honesty of what the dashboard shows (an attacker who can edit data can hide activity).
2. Privacy of the host's activity (usernames, source IPs, process and port lists).
3. Availability of the Pi itself: monitoring must not harm it.

## Trust boundaries
| Boundary | Treatment |
|---|---|
| Log lines (written by sshd, but influenced by remote users) | Untrusted input. Length-bounded, parsed with anchored regexes, malformed lines counted and dropped. Usernames that do not exist locally are never stored. |
| Browser to API | Loopback only. Host header allowlist (DNS rebinding), same-origin and JSON-only checks on changes (CSRF), no CORS, bounded query parameters, errors never echo input. |
| Service account | Unprivileged `sentinelpi` user, `NoNewPrivileges`, read-only system, one writable directory, empty capability set, memory cap. |
| Remote viewing | SSH tunnel to loopback. The API is never put on the LAN. |

## Threats considered
| Threat | Mitigation | Residual risk |
|---|---|---|
| Brute-force SSH | SP-001 detects it and raises an incident | Detection only; it does not block |
| Unexpected new service listening | SP-002 against an approved baseline | A malicious service present at baseline time is "normal" |
| Known attacker tooling running | SP-004 exact process-name watchlist | Renamed binaries evade it |
| Crypto-miner style load | SP-003 sustained CPU, supports other incidents | Cannot tell malicious from busy |
| Log injection (fake "Failed password" lines) | Fields parsed strictly; username only from the log's own fixed positions | A local user able to write to the log or journal can forge events |
| Malicious web page calls the local API | Host and origin checks; no CORS | None known; verified by tests |
| Another local user reads the database | File mode 0600, service-owned directory 0750 | Root can always read it |
| Resource exhaustion by log flood | Per-poll entry cap, dedupe, retention and a size target | A sustained flood is dropped, not all recorded |
| Secrets in the repository | None exist; config holds no credentials | Review before adding any |

## Out of scope
- An attacker with root on the Pi (they can stop or falsify the monitor).
- Network-level monitoring, malware analysis, file integrity checking.
- Multi-user access, authentication, TLS. Add authentication before ever binding beyond loopback.
- Automatic response of any kind.

## Safe use
Run it only on machines you own. Test with synthetic data (`python -m sentinelpi.verify demo`)
or failed logins to an account you control; never aim traffic at other people's systems.
