from datetime import datetime

import pytest

from sentinelpi import verify
from sentinelpi.collectors.auth_sources import parse_syslog_line


def test_percentile_interpolates():
    assert verify._percentile([10.0], 95) == 10.0
    assert verify._percentile([1.0, 2.0, 3.0, 4.0], 50) == pytest.approx(2.5)
    assert verify._percentile([4.0, 1.0], 100) == 4.0


def test_synthetic_attack_lines_are_parseable_and_use_documentation_ips(tmp_path):
    log = tmp_path / "auth.log"
    verify.write_ssh_attack(log, 3)
    lines = log.read_text().splitlines()
    assert len(lines) == 3
    now = datetime.now().astimezone()
    for line in lines:
        parsed = parse_syslog_line(line, now)
        assert parsed is not None
        assert verify.ATTACKER_IP in parsed[3]
    assert verify.ATTACKER_IP.startswith("203.0.113.")  # RFC 5737 documentation range
