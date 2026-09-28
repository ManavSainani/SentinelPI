import pytest
from pydantic import ValidationError

from sentinelpi.config import Settings, load_settings


def test_defaults_are_loopback():
    s = Settings()
    assert s.server.host == "127.0.0.1"
    assert s.exposes_lan is False


def test_load_from_toml(tmp_path):
    f = tmp_path / "c.toml"
    f.write_text('[server]\nhost = "0.0.0.0"\nport = 9000\n')
    s = load_settings(f)
    assert s.server.port == 9000
    assert s.exposes_lan is True


def test_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_settings(tmp_path / "nope.toml")


def test_invalid_port_rejected(tmp_path):
    f = tmp_path / "c.toml"
    f.write_text("[server]\nport = 99999\n")
    with pytest.raises(ValidationError):
        load_settings(f)
