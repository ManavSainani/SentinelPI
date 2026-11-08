# Known limitations

- **One host.** There is no fleet view and no remote agents.
- **Detects, does not prevent.** Nothing is blocked or remediated, by design.
- **SSH is the only authentication source.** No sudo, console or web-login events.
- **Heuristic rules.** Thresholds are sensible defaults, not tuned to a baseline of your traffic. Risk scores are a prioritisation aid, not probabilities.
- **SP-002 needs a human-approved baseline.** Until you capture one, the rule is skipped.
- **Unprivileged means partial visibility.** Process names for ports opened by other users are blank; detection compares protocol and port so it still works.
- **No authentication.** The API trusts loopback. Remote viewing is an SSH tunnel.
- **Time handling.** Stored in UTC, displayed in the browser's local time. Legacy `auth.log` lines carry no year or zone, so they are assumed to be in the host's local time.
- **Temperature** shows `n/a` on hosts that do not report it (most laptops, VMs).
- **Polling.** The dashboard is at most a few seconds behind; the kiosk refreshes every 5 s.
- **Performance figures** are idle measurements on one Pi 4 (see [PERFORMANCE.md](PERFORMANCE.md)).
- **No packaged release.** Install is from a checkout; the frontend is built elsewhere and copied over.
- **Hardware extras (LEDs, buttons, PIR sensor, audio)** are planned in [HARDWARE_PLAN.md](HARDWARE_PLAN.md), not built.
