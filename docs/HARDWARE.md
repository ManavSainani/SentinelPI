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

For each LED (long leg is positive, short leg is negative):
```
GPIO pin ---- 220 ohm resistor ---- LED long leg
                                    LED short leg ---- ground rail (to a GND pin)
```
1. Run one jumper from a GND pin on the breakout to the breadboard's ground rail.
2. Put the three LEDs in separate rows. Short legs to the ground rail (a short jumper each, or the rail row itself).
3. Put one 220 ohm resistor between each LED's long-leg row and the row you wire to its GPIO pin.
4. Jumpers: GPIO17 to the green LED's resistor, GPIO27 to yellow, GPIO22 to red.

A resistor in each LED's path is what stops it burning out (and drawing too much from the pin).
At 3.3 V each LED takes roughly 5 to 6 mA.

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
