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

Your breakout is a Pineworks Labs T-board. Its stem carries only GPIO pins (no ground pins), in
two columns, one numbered breadboard row per pin. Read from the stem labels:

| Row | Left side | Right side |
|---|---|---|
| 8 | GP18 | **GP17** |
| 9 | GP19 | GP16 |
| 10 | GP20 | GP13 |
| 11 | GP21 | GP12 |
| 12 | **GP22** | GP6 |
| 13 | GP23 | GP5 |
| 14 | GP24 | GP4 |
| 15 | GP25 | CE1 |
| 16 | GP26 | CE0 |
| 17 | **GP27** | MOSI |

Any free hole in the same row and on the same side of the centre channel connects to that pin.
Rows 24 and below are free. **Ground and power come from the two small pads on the top wing**
("+ 3.3V -" on the left, "+ 5V -" on the right), not from the stem.

**Part A: build three identical LED circuits (no Pi wires yet).** Left half, rows 26 and below.

| LED | Resistor | LED legs | Ground jumper |
|---|---|---|---|
| Green | row 26 col B to row 28 col B | long leg row 28 col C, short leg row 29 col C | row 29 col D to the left blue (-) rail |
| Yellow | row 32 col B to row 34 col B | long leg row 34 col C, short leg row 35 col C | row 35 col D to the left blue (-) rail |
| Red | row 38 col B to row 40 col B | long leg row 40 col C, short leg row 41 col C | row 41 col D to the left blue (-) rail |

The long leg is positive. The current path: GPIO jumper (row 26/32/38 col A) -> resistor -> LED -> rail.

**Part B: ground.** Connect the "-" hole of the left "+ 3.3V -" pad to the left blue (-) rail
with a male-to-male jumper. If the pad has no header, the plated hole usually holds a jumper
pin firmly enough for testing; for a permanent build, solder a 2-pin header into the pad.
Some long breadboards split their rails halfway down; if no LED lights, suspect that first.

**Part C: the three GPIO jumpers.**
- GP17 (right side, row 8, any free hole F-J) to green's row 26 col A.
- GP27 (left side, row 17) to yellow's row 32 col A.
- GP22 (left side, row 12) to red's row 38 col A.

A wrong pin cannot hurt anything here, because every path has a resistor, but the LED will not
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
