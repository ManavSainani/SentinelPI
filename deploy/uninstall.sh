#!/usr/bin/env bash
# Remove the SentinelPI services. Keeps the database and config unless --purge is given.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "run as root: sudo deploy/uninstall.sh [--purge]" >&2; exit 1; }
systemctl disable --now sentinelpi-leds.service sentinelpi-api.service sentinelpi-monitor.service 2>/dev/null || true
rm -f /etc/systemd/system/sentinelpi-leds.service /etc/systemd/system/sentinelpi-api.service /etc/systemd/system/sentinelpi-monitor.service
systemctl daemon-reload
rm -rf /opt/sentinelpi
if [ "${1:-}" = "--purge" ]; then
  rm -rf /etc/sentinelpi /var/lib/sentinelpi
  id sentinelpi >/dev/null 2>&1 && userdel sentinelpi || true
  echo "removed services, code, config, database and the service account"
else
  echo "removed services and code; kept /etc/sentinelpi and /var/lib/sentinelpi (use --purge to delete)"
fi
