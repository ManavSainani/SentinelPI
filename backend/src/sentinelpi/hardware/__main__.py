"""Hardware check tool:  python -m sentinelpi.hardware <command>

probe        is the GPIO library installed and can it reach the pins?
pins         print the wiring table for the configured pins
check-leds   light each LED in turn so you can confirm the wiring by eye
"""

from __future__ import annotations

import argparse
import glob
import grp
import os
import sys
import time

from sentinelpi.config import HardwareSettings, load_settings

PHYSICAL = {17: 11, 27: 13, 22: 15, 23: 16, 24: 18}


def _pin(bcm: int) -> str:
    phys = PHYSICAL.get(bcm)
    return f"GPIO{bcm}" + (f" (physical pin {phys})" if phys else "")


def print_pins(h: HardwareSettings) -> None:
    rows = [
        ("Green LED", h.green_led_pin, "long leg -> 220 ohm -> this pin; short leg -> ground"),
        ("Yellow LED", h.yellow_led_pin, "long leg -> 220 ohm -> this pin; short leg -> ground"),
        ("Red LED", h.red_led_pin, "long leg -> 220 ohm -> this pin; short leg -> ground"),
        ("Button", h.button_pin, "one side to this pin, other side to ground (internal pull-up)"),
        ("PIR output", h.pir_pin, "sensor OUT; check its voltage first (docs/HARDWARE.md)"),
    ]
    for name, pin, note in rows:
        print(f"{name:11} {_pin(pin):30} {note}")


def probe() -> int:
    ok = True
    try:
        from importlib.metadata import version

        from gpiozero import Device

        print(f"gpiozero {version('gpiozero')}")
        try:
            factory = Device.ensure_pin_factory()
            print(f"pin factory: {type(factory).__name__}")
        except Exception as exc:
            ok = False
            print(f"pin factory: FAILED ({type(exc).__name__}: {exc})")
    except ImportError:
        ok = False
        print("gpiozero: not installed")
    chips = sorted(glob.glob("/dev/gpiochip*"))
    print(f"gpio devices: {', '.join(chips) if chips else 'none found (not a Raspberry Pi?)'}")
    try:
        groups = sorted(grp.getgrgid(g).gr_name for g in os.getgroups())
        print(f"your groups: {', '.join(groups)} ({'has' if 'gpio' in groups else 'NOT in'} gpio)")
    except (KeyError, OSError):
        pass
    print("RESULT:", "ready" if ok and chips else "not ready")
    return 0 if ok and chips else 1


def check_leds(h: HardwareSettings, seconds: float) -> int:
    from sentinelpi.hardware.leds import open_panel

    panel, why = open_panel(h)
    if panel is None:
        print(f"cannot use the LEDs: {why}", file=sys.stderr)
        return 1
    try:
        for name in panel.NAMES:
            print(f"{name.upper()} on for {seconds:.0f} s ...")
            panel.show(**{name: True})
            time.sleep(seconds)
        print("all three on ...")
        panel.show(green=True, yellow=True, red=True)
        time.sleep(seconds)
        print("red blinking (the 'unacknowledged High alert' look) ...")
        panel.show(red=True, blink_red=True)
        time.sleep(seconds * 2)
        print("done: all off")
    finally:
        panel.close()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m sentinelpi.hardware")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("probe")
    sub.add_parser("pins")
    leds = sub.add_parser("check-leds")
    leds.add_argument("--seconds", type=float, default=2.0)
    args = parser.parse_args(argv)
    h = load_settings().hardware
    if args.command == "probe":
        return probe()
    if args.command == "pins":
        print_pins(h)
        return 0
    return check_leds(h, max(0.5, min(args.seconds, 10.0)))


if __name__ == "__main__":
    raise SystemExit(main())
