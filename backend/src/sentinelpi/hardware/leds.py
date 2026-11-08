"""The green / yellow / red status LEDs."""

from __future__ import annotations

from sentinelpi.config import HardwareSettings


class LedPanel:
    """Three LEDs. `show` sets all of them at once so the lights can never disagree."""

    NAMES = ("green", "yellow", "red")

    def __init__(self, pins: dict[str, int]) -> None:
        from gpiozero import LED  # imported late: absent on machines without GPIO support

        self._leds = {name: LED(pins[name]) for name in self.NAMES}

    def show(
        self,
        *,
        green: bool = False,
        yellow: bool = False,
        red: bool = False,
        blink_red: bool = False,
    ) -> None:
        for name, wanted in (("green", green), ("yellow", yellow)):
            (self._leds[name].on if wanted else self._leds[name].off)()
        if red and blink_red:
            self._leds["red"].blink(on_time=0.5, off_time=0.5)
        elif red:
            self._leds["red"].on()
        else:
            self._leds["red"].off()

    def off(self) -> None:
        self.show()

    def close(self) -> None:
        self.off()
        for led in self._leds.values():
            led.close()


def open_panel(settings: HardwareSettings) -> tuple[LedPanel | None, str]:
    """Open the LEDs, or explain why not. Never raises."""
    pins = {
        "green": settings.green_led_pin,
        "yellow": settings.yellow_led_pin,
        "red": settings.red_led_pin,
    }
    try:
        return LedPanel(pins), "ok"
    except ImportError:
        return None, "gpiozero is not installed"
    except Exception as exc:  # gpiozero raises several types (no pin factory, pin in use, ...)
        return None, f"GPIO unavailable: {type(exc).__name__}: {exc}"
