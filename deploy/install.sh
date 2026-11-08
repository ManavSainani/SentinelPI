#!/usr/bin/env bash
# Install or upgrade SentinelPI as two systemd services on this machine.
# Run from the repository root:   sudo deploy/install.sh
# Safe to re-run: it upgrades the code and keeps your config and database.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFIX=/opt/sentinelpi
CONF_DIR=/etc/sentinelpi
SVC_USER=sentinelpi

say() { printf '\n==> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root:  sudo deploy/install.sh"
command -v systemctl >/dev/null || die "systemd is required"
command -v python3 >/dev/null || die "python3 is required"
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' \
  || die "Python 3.11 or newer is required"
python3 -c 'import venv, ensurepip' 2>/dev/null \
  || die "python3-venv is missing:  sudo apt install python3-venv"
[ -f "$REPO/frontend/dist/index.html" ] \
  || die "frontend/dist is missing. Run 'make build' on your Mac and rsync frontend/dist/ here."

if systemctl is-active --quiet sentinelpi-api 2>/dev/null; then
  say "Stopping the running services for the upgrade"
  systemctl stop sentinelpi-api sentinelpi-monitor
fi
if (exec 3<>/dev/tcp/127.0.0.1/8787) 2>/dev/null; then
  die "something is already listening on 127.0.0.1:8787 (a development API?). Stop it first."
fi

say "Creating the service account '$SVC_USER' (no login, no shell)"
if ! id "$SVC_USER" >/dev/null 2>&1; then
  useradd --system --user-group --home-dir /var/lib/sentinelpi --no-create-home \
    --shell /usr/sbin/nologin "$SVC_USER"
fi
for g in systemd-journal adm; do
  getent group "$g" >/dev/null && usermod -aG "$g" "$SVC_USER"
done

say "Installing the code into $PREFIX"
install -d -m 0755 "$PREFIX"
python3 -m venv "$PREFIX/venv"
"$PREFIX/venv/bin/pip" install --quiet --upgrade pip
"$PREFIX/venv/bin/pip" install --quiet --upgrade --force-reinstall --no-deps "$REPO/backend"
"$PREFIX/venv/bin/pip" install --quiet "$REPO/backend"
rm -rf "$PREFIX/frontend"
install -d -m 0755 "$PREFIX/frontend"
cp -r "$REPO/frontend/dist" "$PREFIX/frontend/dist"
chmod -R a+rX "$PREFIX"

say "Configuration in $CONF_DIR"
install -d -m 0750 -o root -g "$SVC_USER" "$CONF_DIR"
if [ -f "$CONF_DIR/config.toml" ]; then
  echo "keeping your existing $CONF_DIR/config.toml"
else
  install -m 0640 -o root -g "$SVC_USER" "$REPO/deploy/config.pi.toml" "$CONF_DIR/config.toml"
  echo "wrote $CONF_DIR/config.toml"
fi
SENTINELPI_CONFIG="$CONF_DIR/config.toml" "$PREFIX/venv/bin/python" -c \
  'from sentinelpi.config import load_settings; load_settings()' \
  || die "the configuration did not validate"

say "Installing and starting the services"
install -m 0644 "$REPO/deploy/systemd/sentinelpi-monitor.service" /etc/systemd/system/
install -m 0644 "$REPO/deploy/systemd/sentinelpi-api.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now sentinelpi-monitor.service sentinelpi-api.service
sleep 4
systemctl --no-pager --lines=0 status sentinelpi-monitor sentinelpi-api || true

cat <<MSG

Installed. Next:
  1. Check:      curl -s http://127.0.0.1:8787/api/v1/health
  2. Logs:       journalctl -u sentinelpi-monitor -u sentinelpi-api -f
  3. Port baseline (review the list, then approve it):
       sudo -u $SVC_USER env SENTINELPI_CONFIG=$CONF_DIR/config.toml \\
         $PREFIX/venv/bin/python -m sentinelpi.detection baseline capture
  4. Kiosk (as the desktop user, NOT with sudo):  deploy/kiosk/install-kiosk.sh
The services keep a fresh database at /var/lib/sentinelpi, separate from any development one.
MSG
