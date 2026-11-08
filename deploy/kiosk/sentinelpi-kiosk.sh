#!/usr/bin/env bash
# Open the SentinelPI kiosk screen in full-screen Chromium and keep it open.
# Started by the desktop session (see install-kiosk.sh). Display-only: no keyboard needed.
URL="${SENTINELPI_KIOSK_URL:-http://127.0.0.1:8787/#/kiosk}"
HEALTH="${URL%%#*}api/v1/health"

BROWSER=""
for b in chromium chromium-browser; do
  command -v "$b" >/dev/null 2>&1 && { BROWSER="$b"; break; }
done
[ -n "$BROWSER" ] || { echo "sentinelpi-kiosk: chromium is not installed" >&2; exit 1; }

# Give the API up to two minutes after boot instead of opening an error page.
for _ in $(seq 1 60); do
  curl -fsS --max-time 2 "$HEALTH" >/dev/null 2>&1 && break
  sleep 2
done

while true; do
  "$BROWSER" \
    --kiosk \
    --noerrdialogs \
    --disable-infobars \
    --no-first-run \
    --disable-session-crashed-bubble \
    --disable-features=Translate \
    --password-store=basic \
    --autoplay-policy=no-user-gesture-required \
    --user-data-dir="$HOME/.cache/sentinelpi-kiosk" \
    "$URL"
  sleep 5   # if the browser is closed or crashes, bring it back
done
