# SentinelPi physical layer: plan (not yet built)

This extends the software MVP with physical indicators and inputs. Nothing here is required for
Phases 6-11, and every hardware feature must degrade cleanly on a machine with no GPIO (macOS,
CI): the status is reported as `unavailable`, never an error.

## Parts on hand
Raspberry Pi 4 (4 GB); HDMI display with speakers; breadboard with GPIO breakout and 40-pin
ribbon; green, yellow and red LEDs; 220 ohm and 10k ohm resistors; push buttons; PIR motion
sensor (looks like an HC-SR501; confirm from its board markings); jumper wires.

## Roles
| Part | Role | Depends on |
|---|---|---|
| Green / yellow / red LEDs | Green = monitoring healthy. Yellow = warning (open Low/Medium incident, degraded collector, or stale monitor heartbeat). Red = open High/Critical incident, blinking until acknowledged, then steady. | incident status (Phase 6) |
| Push button | Acknowledge the current alert: OPEN -> ACKNOWLEDGED, audited as "physical button". Acknowledging is not resolving. | incident lifecycle (Phase 6) |
| PIR motion sensor | Low-severity "motion" events, coalesced (the sensor retriggers constantly), retained briefly. Correlated with login activity as context only: motion near the Pi during an SSH login is interesting, not proof of anything. | new event source (schema change) |
| HDMI display | Kiosk dashboard on the Pi; full-screen security alert for open High/Critical incidents. | API + dashboard (Phases 7-8) |
| HDMI speakers | Short audible alert for High/Critical only, with a mute. | kiosk or a small audio helper |

## Design decisions
- **One small hardware package** behind an interface, with a fake backend for tests and the Mac.
  GPIO library: `gpiozero` (its `lgpio` backend on current Pi OS). To be verified on your Pi.
- **LED state is derived from the database** by a separate loop, not from the web UI, so the
  lights keep working if the browser or dashboard is down.
- **The button is physical access, not authentication.** Anyone standing at the Pi can acknowledge
  an alert. That is acceptable for a home lab; it will be documented and every use is audited.
- **Motion data is presence data.** It reveals when someone is in the room, so it stays local,
  has a short retention window, and can be disabled in the config.
- **Schema change needed for PIR events:** `events.source` has a CHECK constraint that does not
  list a physical source. SQLite cannot alter a CHECK in place, so this will be a migration that
  rebuilds the table, tested like the existing ones. Done in that phase, not before.

## Electrical notes (for the wiring step)
- Power the Pi off before touching wiring, including the ribbon cable (red stripe = pin 1).
- Every LED gets its own 220 ohm series resistor. At 3.3 V that is roughly 5-6 mA per LED.
- Buttons use the Pi's internal pull-up, wired between a GPIO pin and ground, so the 10k
  resistors are not needed for them.
- HC-SR501-type sensors are powered from 5 V but are generally documented as having a 3.3 V
  output. That must be checked on your exact module before its output goes near a GPIO pin.
  They need about 30-60 seconds to settle after power-up and have sensitivity and delay trimmers.
- Exact pins and a wiring diagram come with the step that needs them, along with a small
  standalone check script so each part is proven before the app depends on it.

## Suggested order
1. Phases 6-8 as planned (incidents, API, dashboard).
2. Kiosk mode on the HDMI display (also the Phase 10 packaging work).
3. LEDs, then button, then PIR, then audio, each with a hardware check and fake-backend tests.
