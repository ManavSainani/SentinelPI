"""Static checks on the deployment files. They cannot start systemd, but they catch typos,
a config template that no longer validates, and hardening that quietly goes missing."""

import configparser
import subprocess
from pathlib import Path

import pytest

from sentinelpi.config import load_settings

DEPLOY = Path(__file__).resolve().parents[2] / "deploy"
UNITS = ["sentinelpi-monitor.service", "sentinelpi-api.service"]


def _unit(name: str) -> configparser.ConfigParser:
    cp = configparser.ConfigParser(strict=False, interpolation=None)
    cp.optionxform = str  # type: ignore[assignment,method-assign]
    cp.read(DEPLOY / "systemd" / name)
    return cp


@pytest.mark.parametrize("name", UNITS)
def test_units_run_unprivileged_and_hardened(name):
    svc = _unit(name)["Service"]
    assert svc["User"] == "sentinelpi"
    assert svc["NoNewPrivileges"] == "yes"
    assert svc["ProtectSystem"] == "strict"
    assert svc["ReadWritePaths"] == "/var/lib/sentinelpi"
    assert svc["CapabilityBoundingSet"] == ""
    assert svc["Restart"] == "on-failure"
    text = (DEPLOY / "systemd" / name).read_text()  # Environment= appears twice
    assert "Environment=SENTINELPI_CONFIG=/etc/sentinelpi/config.toml" in text


def test_each_unit_starts_a_real_module():
    for name, module in zip(UNITS, ["sentinelpi.monitor", "sentinelpi.main"], strict=True):
        exec_start = _unit(name)["Service"]["ExecStart"]
        assert exec_start.endswith(f"-m {module}")
        __import__(module)


def test_api_waits_for_the_monitor():
    unit = _unit("sentinelpi-api.service")["Unit"]
    assert "sentinelpi-monitor.service" in unit["After"]


def test_monitor_can_read_the_journal():
    assert (
        "systemd-journal" in _unit("sentinelpi-monitor.service")["Service"]["SupplementaryGroups"]
    )


def test_service_config_template_validates_and_stays_on_loopback():
    s = load_settings(DEPLOY / "config.pi.toml")
    assert s.server.host == "127.0.0.1"
    assert not s.exposes_lan
    assert s.storage.db_path.startswith("/var/lib/sentinelpi/")
    assert s.frontend_dist == "/opt/sentinelpi/frontend/dist"


@pytest.mark.parametrize(
    "script",
    ["install.sh", "uninstall.sh", "kiosk/install-kiosk.sh", "kiosk/sentinelpi-kiosk.sh"],
)
def test_scripts_have_valid_syntax_and_are_executable(script):
    path = DEPLOY / script
    assert path.stat().st_mode & 0o111, f"{script} is not executable"
    subprocess.run(["bash", "-n", str(path)], check=True)


def test_kiosk_targets_the_kiosk_route_on_loopback():
    text = (DEPLOY / "kiosk" / "sentinelpi-kiosk.sh").read_text()
    assert "127.0.0.1:8787/#/kiosk" in text
    assert "--kiosk" in text
