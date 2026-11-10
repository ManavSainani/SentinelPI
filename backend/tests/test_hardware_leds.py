import pytest
from gpiozero import Device
from gpiozero.pins.mock import MockFactory
from pydantic import ValidationError

from sentinelpi.config import HardwareSettings
from sentinelpi.hardware import open_panel
from sentinelpi.hardware.__main__ import main


@pytest.fixture
def mock_pins():
    old = Device.pin_factory
    Device.pin_factory = MockFactory()
    yield Device.pin_factory
    Device.pin_factory.reset()
    Device.pin_factory = old


def _state(factory, pin):
    return factory.pin(pin).state


def test_panel_drives_the_configured_pins(mock_pins):
    s = HardwareSettings(green_led_pin=5, yellow_led_pin=6, red_led_pin=13)
    panel, why = open_panel(s)
    assert panel is not None and why == "ok"
    panel.show(green=True)
    assert (_state(mock_pins, 5), _state(mock_pins, 6), _state(mock_pins, 13)) == (1, 0, 0)
    panel.show(yellow=True, red=True)
    assert (_state(mock_pins, 5), _state(mock_pins, 6), _state(mock_pins, 13)) == (0, 1, 1)
    panel.close()
    assert (_state(mock_pins, 5), _state(mock_pins, 6), _state(mock_pins, 13)) == (0, 0, 0)


def test_show_replaces_the_whole_state_so_lights_cannot_disagree(mock_pins):
    panel, _ = open_panel(HardwareSettings())
    panel.show(green=True, yellow=True, red=True)
    panel.show(red=True)  # earlier greens and yellows must go out
    s = HardwareSettings()
    assert (_state(mock_pins, s.green_led_pin), _state(mock_pins, s.yellow_led_pin)) == (0, 0)
    assert _state(mock_pins, s.red_led_pin) == 1
    panel.close()


def test_blinking_red_stops_when_steady_or_off(mock_pins):
    panel, _ = open_panel(HardwareSettings())
    panel.show(red=True, blink_red=True)
    panel.show(red=True)
    assert _state(mock_pins, HardwareSettings().red_led_pin) == 1
    panel.show()
    assert _state(mock_pins, HardwareSettings().red_led_pin) == 0
    panel.close()


def test_open_panel_reports_instead_of_raising_without_gpio(monkeypatch):
    class Broken:
        def __init__(self, *_a, **_k):
            raise RuntimeError("no pin factory")

    monkeypatch.setattr("gpiozero.LED", Broken)
    panel, why = open_panel(HardwareSettings())
    assert panel is None and "RuntimeError" in why


def test_pins_must_be_distinct_and_valid():
    with pytest.raises(ValidationError, match="only one part"):
        HardwareSettings(green_led_pin=17, yellow_led_pin=17)
    with pytest.raises(ValidationError):
        HardwareSettings(red_led_pin=40)


def test_hardware_is_off_by_default():
    assert HardwareSettings().enabled is False


def test_pins_command_prints_the_wiring(capsys):
    assert main(["pins"]) == 0
    out = capsys.readouterr().out
    assert "Green LED" in out and "GPIO17" in out and "physical pin 11" in out


def test_check_leds_command_runs_against_mock_pins(mock_pins, capsys):
    assert main(["check-leds", "--seconds", "0.5"]) == 0
    assert "done: all off" in capsys.readouterr().out


def test_probe_reports_without_crashing(mock_pins, capsys):
    from sentinelpi.hardware.__main__ import probe

    probe()  # result depends on the machine; it must print a verdict, never raise
    out = capsys.readouterr().out
    assert "gpiozero 2." in out and "RESULT:" in out


def test_check_button_sees_presses_and_flags_a_stuck_button(mock_pins, capsys, monkeypatch):
    import threading
    import time

    h = HardwareSettings()
    pin = mock_pins.pin(h.button_pin)

    def press():
        time.sleep(0.3)
        pin.drive_low()
        time.sleep(0.1)
        pin.drive_high()

    threading.Thread(target=press).start()
    assert main(["check-button", "--seconds", "2"]) == 0
    assert "saw 1 press" in capsys.readouterr().out

    import gpiozero

    # a button that is always joined reads pressed at rest
    monkeypatch.setattr(gpiozero.Button, "is_pressed", property(lambda self: True))
    assert main(["check-button", "--seconds", "2"]) == 1
    assert "rotate it" in capsys.readouterr().out


def test_a_busy_pin_tells_you_to_stop_the_service(monkeypatch, capsys):
    import gpiozero

    class Busy:
        def __init__(self, *_a, **_k):
            raise RuntimeError("error: 'GPIO busy'")

    monkeypatch.setattr(gpiozero, "Button", Busy)
    assert main(["check-button", "--seconds", "2"]) == 1
    assert "systemctl stop sentinelpi-leds" in capsys.readouterr().err
