# Hardware build guide

Built in small steps, each proven on its own before the app depends on it. Plan and reasons:
[HARDWARE_PLAN.md](HARDWARE_PLAN.md). Pins use BCM (GPIO) numbers, with the physical header pin
in brackets. Change them in `[hardware]` in the config if you prefer others.

| Part | GPIO (physical pin) | Step |
|---|---|---|
| Green LED | GPIO17 (11) | 1 |
| Yellow LED | GPIO27 (13) | 1 |
| Red LED | GPIO22 (15) | 1 |
| Button | GPIO23 (16) | 2 |
| PIR output | GPIO24 (18) | 3 |
| Ground | any GND, e.g. pin 14 or 20 | all |

## Step 1: three LEDs
**Power the Pi off and unplug it before wiring.** (`sudo poweroff`, wait for the green light to
stop, then unplug.) Keep the ribbon cable's red stripe on pin 1 end.

Your breadboard has the Pi's T-shaped breakout plugged into the top rows, straddling the centre
channel. Each breakout pin owns one numbered row. Holes A-D in a row connect to that row's pin
on the left side of the breakout (F-J on the right side), so you can plug a wire into any free
hole beside the pin. Rows 24 and below are free.

**Part A: build three identical LED circuits (no Pi wires yet).** Left half, columns A-E.
Rows are numbered on the breadboard's edge.

| LED | Resistor | LED legs | Ground jumper |
|---|---|---|---|
| Green | row 26 col B to row 28 col B | long leg row 28 col C, short leg row 29 col C | row 29 col D to the left blue (-) rail |
| Yellow | row 32 col B to row 34 col B | long leg row 34 col C, short leg row 35 col C | row 35 col D to the left blue (-) rail |
| Red | row 38 col B to row 40 col B | long leg row 40 col C, short leg row 41 col C | row 41 col D to the left blue (-) rail |

The long leg is the positive one; if you cannot tell, it is the leg that is not flat against the
LED's rim. The current path is: GPIO jumper (row 26/32/38 col A) -> resistor -> LED -> rail.

**Part B: ground.** One jumper from any breakout row labelled GND (hole A-D beside it) to the
same left blue (-) rail. Some long breadboards split their rails halfway down; if no LED lights,
that is the first thing to suspect.

**Part C: the three GPIO jumpers.** Read the tiny labels printed on the breakout beside each
row. A jumper from the row labelled 17 to green's row 26 col A, 27 to yellow's row 32 col A, and
22 to red's row 38 col A. If a label is hard to read, count from a clearly labelled neighbour;
the physical pin numbers in the table above (11, 13, 15) are the order on the Pi's header. A
wrong pin cannot hurt anything here, because every path has a resistor, but the LED will not
respond to the check tool.

### Check it
When the `sentinelpi-leds` service is running it owns the pins, so the check commands report
"GPIO busy". Stop it first with `sudo systemctl stop sentinelpi-leds`, run the check, then
`sudo systemctl start sentinelpi-leds`.

```bash
cd ~/SentinelPI && source .venv/bin/activate
python -m sentinelpi.hardware probe       # expect: RESULT: ready
python -m sentinelpi.hardware check-leds  # green, yellow, red, all, then red blinking
```
If one LED stays dark: flip it (wrong way round is the usual cause), check that its resistor and
jumper are in the same breadboard row groups, and re-run. If `probe` says not ready, see below.

## Step 1b: make the LEDs show live status
The lights are driven by their own small service that reads the incident database, not the web
page, so they keep working if the dashboard or browser is down.

| Light | Meaning |
|---|---|
| Green | Monitor running, metrics fresh, no open incident |
| Yellow | An open Low or Medium incident, a monitor that has gone quiet, or stale metrics |
| Red, blinking | An open High or Critical incident that nobody has acknowledged |
| Red, steady | High or Critical incidents exist but all are acknowledged |

If it cannot read the database, it shows yellow rather than a false green. At start-up all three
come on for one second as a lamp test.

Turn it on (Pi, after the services are installed):
```bash
printf '\n[hardware]\nenabled = true\n' | sudo tee -a /etc/sentinelpi/config.toml
cd ~/SentinelPI && git pull && sudo deploy/install.sh
journalctl -u sentinelpi-leds -n 20 --no-pager
```
The installer enables `sentinelpi-leds` only when `[hardware] enabled = true` and the GPIO
library is present (`sudo apt install python3-lgpio`). Try it: run the failed-login loop from your
Mac (see DEMO.md). Red should blink; acknowledge the incident on the dashboard and red turns
steady; resolve it and green returns.

To watch it without the service: `python -m sentinelpi.hardware run` (Ctrl+C to stop; it reads the
database named in your config, so use `SENTINELPI_CONFIG=/etc/sentinelpi/config.toml` and
`sudo -u sentinelpi` to read the service's data).

## Pi software setup for GPIO
```bash
sudo apt install -y python3-lgpio
sed -i 's/include-system-site-packages = false/include-system-site-packages = true/' ~/SentinelPI/.venv/pyvenv.cfg
pip install gpiozero==2.0.1
```
Your user must be in the `gpio` group (the default on Raspberry Pi OS). The services will get
the same access when the status loop is added.

## Step 2: acknowledge button
Wiring: the interactive guide shows it; in words, a push button straddling the centre channel
(legs in rows 47 and 49), GP23 (left side, row 13) to row 47, and row 49 to the left blue (-)
rail. No resistor: the pin uses the Pi's internal pull-up. Check it before relying on it:
```bash
python -m sentinelpi.hardware check-button
```
It reports "pressed" and "released", and tells you to rotate the button a quarter turn if it
reads pressed at rest (its legs are joined the wrong way round).

What it does: hold the button for half a second and it acknowledges the incident the kiosk is
showing (the most severe open one, newest first). The kiosk drops back to its calm screen within
about 5 seconds, and the red LED goes from blinking to steady. With two incidents open, the next
press clears the next one. A press with nothing open does nothing. A quick tap is ignored, so a
brush or a flicker on the wire cannot acknowledge anything.

It is physical access, not a login: anyone at the Pi can press it. Every press is recorded in the
incident's audit trail with the actor "button". Acknowledging is not resolving: the incident
stays open for review, and you resolve it from the dashboard.

## Coming next
- Step 3: HC-SR501 PIR. It is powered from 5 V; its output is documented as 3.3 V but must be
  measured on your module before it touches a GPIO pin. Wiring waits for that check.
- Step 4: audio over the monitor's built-in HDMI speakers (no wiring).
