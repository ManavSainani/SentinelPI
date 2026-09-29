"""Configuration loading: TOML file -> validated settings, with safe defaults."""

from __future__ import annotations

import os
import tomllib
from pathlib import Path

from pydantic import BaseModel, Field


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


class Settings(BaseModel):
    server: ServerSettings = ServerSettings()
    storage: StorageSettings = StorageSettings()
    collection: CollectionSettings = CollectionSettings()
    retention: RetentionSettings = RetentionSettings()
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
