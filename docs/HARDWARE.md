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
```bash
cd ~/SentinelPI && source .venv/bin/activate
python -m sentinelpi.hardware probe       # expect: RESULT: ready
python -m sentinelpi.hardware check-leds  # green, yellow, red, all, then red blinking
```
If one LED stays dark: flip it (wrong way round is the usual cause), check that its resistor and
jumper are in the same breadboard row groups, and re-run. If `probe` says not ready, see below.

## Pi software setup for GPIO
```bash
sudo apt install -y python3-lgpio
sed -i 's/include-system-site-packages = false/include-system-site-packages = true/' ~/SentinelPI/.venv/pyvenv.cfg
pip install gpiozero==2.0.1
```
Your user must be in the `gpio` group (the default on Raspberry Pi OS). The services will get
the same access when the status loop is added.

## Coming next
- Step 2: acknowledge button (GPIO23 to ground, internal pull-up, no resistor).
- Step 3: HC-SR501 PIR. It is powered from 5 V; its output is documented as 3.3 V but must be
  measured on your module before it touches a GPIO pin. Wiring waits for that check.
- Step 4: audio over the monitor's built-in HDMI speakers (no wiring).
