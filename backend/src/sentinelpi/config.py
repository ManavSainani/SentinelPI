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


class Settings(BaseModel):
    server: ServerSettings = ServerSettings()
    storage: StorageSettings = StorageSettings()
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
