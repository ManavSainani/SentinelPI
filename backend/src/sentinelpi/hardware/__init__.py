"""Physical indicators for the Raspberry Pi (LEDs now; button and PIR sensor later).

Everything here degrades cleanly: with no GPIO library or no pins (a Mac, CI), `open_panel`
returns None and a reason, never an exception.
"""

from sentinelpi.hardware.leds import LedPanel, open_panel

__all__ = ["LedPanel", "open_panel"]
