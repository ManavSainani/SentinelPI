"""Configuration loading: TOML file -> validated settings, with safe defaults."""

from __future__ import annotations

import ipaddress
import os
import re
import tomllib
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class ServerSettings(BaseModel):
    # Secure by default: loopback only. LAN exposure must be an explicit opt-in.
    host: str = "127.0.0.1"
    port: int = Field(default=8787, ge=1, le=65535)


class StorageSettings(BaseModel):
    db_path: str = "data/sentinelpi.db"


class CollectionSettings(BaseModel):
    disk_path: str = "/"
    process_limit: int = Field(default=50, ge=1, le=500)
    port_limit: int = Field(default=200, ge=1, le=1000)


class RetentionSettings(BaseModel):
    events_days: int = Field(default=14, ge=1, le=365)
    metrics_days: int = Field(default=7, ge=1, le=90)  # high volume: pruned sooner
    snapshot_days: int = Field(default=3, ge=1, le=30)  # process + port snapshots
    incident_days: int = Field(default=90, ge=1, le=730)  # resolved/false-positive only
    max_db_mb: int = Field(default=256, ge=8, le=4096)  # size target, see retention.py


_UNIT_RE = re.compile(r"^[A-Za-z0-9:_.@-]{1,128}\.service$")


class AuthSettings(BaseModel):
    # Unit names go straight into a journalctl argument, so they are validated strictly.
    journal_units: list[str] = Field(default=["ssh.service", "sshd.service"], max_length=5)
    auth_log_paths: list[str] = Field(
        default=["/var/log/auth.log", "/var/log/secure"], max_length=5
    )
    initial_lookback_minutes: int = Field(default=15, ge=1, le=1440)  # first poll only
    max_entries_per_poll: int = Field(default=1000, ge=10, le=10000)

    @field_validator("journal_units")
    @classmethod
    def _valid_units(cls, units: list[str]) -> list[str]:
        if not units or not all(_UNIT_RE.match(u) for u in units):
            raise ValueError("journal_units must be systemd unit names like 'ssh.service'")
        return units


class _Strict(BaseModel):
    """Detection and monitor settings reject unknown keys, so a typo in the TOML file fails
    loudly instead of silently leaving a threshold at its default."""

    model_config = ConfigDict(extra="forbid")


_PORT_KEY = re.compile(r"^(tcp|udp)/([1-9][0-9]{0,4})$")
_PROCESS_NAME = re.compile(r"^[\w .+()-]{1,64}$")
DEFAULT_WATCHLIST = [
    "nc",
    "ncat",
    "netcat",
    "nmap",
    "masscan",
    "hydra",
    "john",
    "xmrig",
    "minerd",
]


class SshFailuresRule(_Strict):  # SP-001
    enabled: bool = True
    threshold: int = Field(default=5, ge=2, le=1000)  # failed attempts from one IP...
    window_minutes: int = Field(default=5, ge=1, le=60)  # ...within this window (inclusive)
    cooldown_minutes: int = Field(default=30, ge=1, le=10080)
    # Source IPs never alerted on. Empty by default: an allowlist is a blind spot, so only
    # add addresses you fully control.
    ignored_source_ips: list[str] = Field(default_factory=list, max_length=50)

    @field_validator("ignored_source_ips")
    @classmethod
    def _valid_ips(cls, ips: list[str]) -> list[str]:
        return [str(ipaddress.ip_address(ip.strip())) for ip in ips]


class NewPortRule(_Strict):  # SP-002
    enabled: bool = True
    protocols: list[Literal["tcp", "udp"]] = Field(default=["tcp", "udp"], min_length=1)
    ignored_ports: list[str] = Field(default_factory=list, max_length=200)  # e.g. "udp/5353"
    cooldown_minutes: int = Field(default=1440, ge=1, le=10080)
    max_per_run: int = Field(default=20, ge=1, le=100)

    @field_validator("ignored_ports")
    @classmethod
    def _valid_ports(cls, ports: list[str]) -> list[str]:
        bad = [p for p in ports if not _PORT_KEY.match(p) or int(p.split("/")[1]) > 65535]
        if bad:
            raise ValueError("ignored_ports entries must look like 'tcp/8080' or 'udp/5353'")
        return ports


class CpuRule(_Strict):  # SP-003
    enabled: bool = True
    cpu_percent: float = Field(default=90.0, ge=1.0, le=99.9)  # strictly above this...
    window_minutes: int = Field(default=5, ge=1, le=60)  # ...for the whole window
    min_samples: int = Field(default=10, ge=3, le=1000)
    max_gap_seconds: int = Field(default=60, ge=5, le=600)  # larger gaps = window not covered
    high_cpu_percent: float = Field(default=98.0, ge=1.0, le=100.0)  # average >= this: Medium
    cooldown_minutes: int = Field(default=30, ge=1, le=10080)

    @model_validator(mode="after")
    def _high_not_below_threshold(self) -> CpuRule:
        if self.high_cpu_percent < self.cpu_percent:
            raise ValueError("high_cpu_percent must be >= cpu_percent")
        return self


class WatchlistRule(_Strict):  # SP-004
    enabled: bool = True
    process_names: list[str] = Field(
        default_factory=lambda: list(DEFAULT_WATCHLIST), max_length=100
    )
    cooldown_minutes: int = Field(default=360, ge=1, le=10080)

    @field_validator("process_names")
    @classmethod
    def _valid_names(cls, names: list[str]) -> list[str]:
        cleaned = [n.strip() for n in names]
        if not all(_PROCESS_NAME.match(n) for n in cleaned):
            raise ValueError("process_names must be plain process names (max 64 characters)")
        return cleaned


class ScoringSettings(_Strict):
    """Heuristic risk points (spec section 7). A prioritization aid, not a probability."""

    ssh_failures: int = Field(default=35, ge=0, le=100)
    new_listening_port: int = Field(default=20, ge=0, le=100)
    watchlisted_process: int = Field(default=30, ge=0, le=100)
    sustained_cpu: int = Field(default=10, ge=0, le=100)
    independent_rule_bonus: int = Field(default=10, ge=0, le=100)  # per extra distinct rule
    band_medium: int = Field(default=25, ge=1, le=99)
    band_high: int = Field(default=50, ge=1, le=99)
    band_critical: int = Field(default=75, ge=1, le=100)

    @model_validator(mode="after")
    def _bands_ascending(self) -> ScoringSettings:
        if not self.band_medium < self.band_high < self.band_critical:
            raise ValueError("score bands must satisfy band_medium < band_high < band_critical")
        return self


class DetectionSettings(_Strict):
    max_snapshot_age_minutes: int = Field(default=10, ge=1, le=1440)  # stale data is not judged
    ssh_failures: SshFailuresRule = SshFailuresRule()
    new_port: NewPortRule = NewPortRule()
    cpu: CpuRule = CpuRule()
    watchlist: WatchlistRule = WatchlistRule()
    scoring: ScoringSettings = ScoringSettings()


class MonitorSettings(_Strict):
    metrics_interval_seconds: int = Field(default=10, ge=2, le=3600)
    snapshot_interval_seconds: int = Field(default=60, ge=10, le=3600)  # processes + ports
    auth_interval_seconds: int = Field(default=15, ge=5, le=3600)
    detection_interval_seconds: int = Field(default=30, ge=5, le=3600)
    retention_interval_seconds: int = Field(default=3600, ge=60, le=86400)


class Settings(BaseModel):
    server: ServerSettings = ServerSettings()
    storage: StorageSettings = StorageSettings()
    collection: CollectionSettings = CollectionSettings()
    retention: RetentionSettings = RetentionSettings()
    auth: AuthSettings = AuthSettings()
    detection: DetectionSettings = DetectionSettings()
    monitor: MonitorSettings = MonitorSettings()
    # Built frontend (Vite output). Relative paths resolve from the working directory.
    frontend_dist: str = "frontend/dist"

    @property
    def exposes_lan(self) -> bool:
        return self.server.host not in {"127.0.0.1", "localhost", "::1"}


def load_settings(path: str | os.PathLike[str] | None = None) -> Settings:
    """Load settings from `path`, or $SENTINELPI_CONFIG, or defaults if neither exists."""
    candidate = path or os.environ.get("SENTINELPI_CONFIG")
    if not candidate:
        return Settings()
    p = Path(candidate)
    if not p.is_file():
        raise FileNotFoundError(f"Config file not found: {p}")
    with p.open("rb") as f:
        data = tomllib.load(f)
    return Settings.model_validate(data)
