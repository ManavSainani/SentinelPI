# Deploying SentinelPI on the Raspberry Pi

Two systemd services run as an unprivileged `sentinelpi` account (no login, no shell):

| Service | Does | Listens |
|---|---|---|
| `sentinelpi-monitor` | collectors, detection, incidents, retention | nothing |
| `sentinelpi-api` | REST API and dashboard | `127.0.0.1:8787` only |

The kiosk is a separate piece: your desktop user's session opens full-screen Chromium on the
HDMI monitor at login.

## 1. Install the services
On the Mac: `make build`, commit/push, then rsync the build (it is git-ignored):
`rsync -av frontend/dist/ msainani@manavpi.local:~/SentinelPI/frontend/dist/`

On the Pi:
```bash
cd ~/SentinelPI && git pull
# stop any development API/monitor first (Ctrl+C), then:
sudo deploy/install.sh
curl -s http://127.0.0.1:8787/api/v1/health
```
The installer builds a virtualenv in `/opt/sentinelpi`, writes `/etc/sentinelpi/config.toml`
(kept on upgrades), and stores data in `/var/lib/sentinelpi`. Re-run it to upgrade after a
`git pull` (and a fresh rsync of `frontend/dist`).

The services use a **new, empty database**, separate from development, so the port baseline
must be captured again. Review the list it prints, then approve:
```bash
sudo -u sentinelpi env SENTINELPI_CONFIG=/etc/sentinelpi/config.toml \
  /opt/sentinelpi/venv/bin/python -m sentinelpi.detection baseline capture
```

Because the services are unprivileged, ports opened by other users show without a process
name. Detection is unaffected: SP-002 compares protocol and port, and SP-004 reads the process
list, which any user can read.

## 2. Kiosk on the HDMI monitor
As your desktop user (`msainani`), not with sudo:
```bash
cd ~/SentinelPI
deploy/kiosk/install-kiosk.sh
sudo raspi-config nonint do_boot_behaviour B4   # sign in to the desktop automatically
sudo reboot
```
After boot the monitor shows the calm kiosk screen, and goes full screen for High severity or
above. `deploy/kiosk/install-kiosk.sh --remove` undoes it. If the screen blanks after a while,
turn it off with `sudo raspi-config nonint do_blanking 1`.

The script assumes labwc, the default compositor on current Raspberry Pi OS. Check with
`echo $XDG_SESSION_TYPE; echo $XDG_CURRENT_DESKTOP`. If you run something else, tell me and
the autostart line moves to that compositor's file.

## 3. Everyday commands
```bash
systemctl status sentinelpi-monitor sentinelpi-api
journalctl -u sentinelpi-monitor -u sentinelpi-api -f
sudo systemctl restart sentinelpi-monitor sentinelpi-api
sudo deploy/uninstall.sh          # keeps data; add --purge to delete everything
```
View the dashboard from the Mac through the tunnel as before:
`ssh -L 8787:127.0.0.1:8787 msainani@manavpi.local`.

## Not done here
Binding to the LAN needs authentication first; the API deliberately has none. Audio and GPIO
come in the hardware phase.
