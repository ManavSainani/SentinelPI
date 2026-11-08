#!/usr/bin/env bash
# Make the Pi's desktop session open the SentinelPI kiosk at login (labwc / Raspberry Pi OS).
# Run as the desktop user, without sudo:   deploy/kiosk/install-kiosk.sh
# Undo with:                               deploy/kiosk/install-kiosk.sh --remove
set -euo pipefail
[ "$(id -u)" -ne 0 ] || { echo "run as your normal desktop user, not root" >&2; exit 1; }

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$HOME/.local/bin/sentinelpi-kiosk"
CFG="$HOME/.config/labwc"
AUTOSTART="$CFG/autostart"
MARK="# sentinelpi-kiosk"

if [ "${1:-}" = "--remove" ]; then
  [ -f "$AUTOSTART" ] && sed -i "/$MARK/d" "$AUTOSTART"
  rm -f "$BIN"
  echo "kiosk autostart removed (the desktop's own autostart lines were left alone)"
  exit 0
fi

mkdir -p "$HOME/.local/bin" "$CFG"
install -m 0755 "$HERE/sentinelpi-kiosk.sh" "$BIN"

# A user autostart replaces the system one, so start from the system lines (panel, wallpaper).
if [ ! -f "$AUTOSTART" ] && [ -f /etc/xdg/labwc/autostart ]; then
  cp /etc/xdg/labwc/autostart "$AUTOSTART"
fi
touch "$AUTOSTART"
grep -q "$MARK" "$AUTOSTART" || echo "$BIN & $MARK" >> "$AUTOSTART"

echo "kiosk installed. Log out and in, or reboot, to start it."
echo "To make the Pi sign in by itself:  sudo raspi-config nonint do_boot_behaviour B4"
