# Demo script (about 5 minutes)

Use the Pi with the kiosk on the HDMI monitor and the dashboard open on a laptop through the
SSH tunnel (`ssh -L 8787:127.0.0.1:8787 msainani@manavpi.local`). Everything below is safe:
the "attacks" are failed logins to an account you do not have, made from your own machine.

1. **Calm state.** Show the kiosk: clock, "All quiet", live CPU, memory and disk. Open the
   dashboard Overview: same data, with the last-hour activity ribbon.
2. **Attack.** From the laptop:
   `for i in $(seq 1 8); do ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no fakeuser@manavpi.local true; done`
   (press Enter at each password prompt).
3. **Detection.** Within about a minute the kiosk goes full screen: High severity, "Repeated
   SSH failures", the source address, risk score and the rules that fired.
4. **Explain it.** On the dashboard open the incident: summary, the score breakdown, the plain
   explanation of rule SP-001, and the timeline of evidence events. Point out that the fake
   username was recorded as "unknown user", not stored.
5. **Second rule, escalation.** On the Pi, `cp /bin/sleep /tmp/nc && /tmp/nc 600 &` then open a
   listener (`python3 -m http.server 9999 --bind 127.0.0.1 &`). SP-004 and SP-002 join one host
   incident and SP-005 raises it to High. (Capture the port baseline first, see DEPLOYMENT.md.)
6. **Lifecycle.** Acknowledge the incident; the kiosk returns to calm. Show the audit trail,
   then resolve it. Try to reopen it: the API refuses with 409.
7. **Resilience.** `sudo systemctl stop sentinelpi-api`: the kiosk keeps the last state and
   marks it stale, then shows offline. Start it again and it recovers by itself.
8. **Clean up.** `kill %1 %2; rm /tmp/nc`.

For a no-hardware version, run `python -m sentinelpi.verify demo` and read the PASS lines.
