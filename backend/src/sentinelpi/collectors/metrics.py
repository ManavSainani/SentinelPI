"""System metrics: CPU, memory, disk, uptime, network counters, optional temperature."""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

import psutil
from pydantic import BaseModel, Field

from sentinelpi.collectors.base import (
    CollectionResult,
    CollectorState,
    make_status,
    utcnow,
)

NAME = "metrics"
DEFAULT_THERMAL_PATH = Path("/sys/class/thermal/thermal_zone0/temp")
_PREFERRED_SENSORS = ("cpu_thermal", "cpu-thermal", "coretemp", "k10temp", "soc_thermal")
_TEMP_MIN_C, _TEMP_MAX_C = -40.0, 150.0  # outside this is a bad reading, not a temperature


class MetricsSample(BaseModel):
    timestamp: datetime
    cpu_percent: float = Field(ge=0, le=100)
    memory_percent: float = Field(ge=0, le=100)
    disk_percent: float = Field(ge=0, le=100)
    temperature_c: float | None = None
    uptime_seconds: float = Field(ge=0)
    net_rx_bytes: int | None = Field(default=None, ge=0)
    net_tx_bytes: int | None = Field(default=None, ge=0)


def _clamp_pct(value: float) -> float:
    return max(0.0, min(100.0, float(value)))


def _plausible(celsius: float) -> float | None:
    return celsius if _TEMP_MIN_C <= celsius <= _TEMP_MAX_C else None


class MetricsCollector:
    def __init__(
        self,
        disk_path: str = "/",
        psutil_mod: Any = psutil,
        thermal_path: Path = DEFAULT_THERMAL_PATH,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._ps = psutil_mod
        self._disk_path = disk_path
        self._thermal_path = thermal_path
        self._clock = clock
        try:  # The first cpu_percent(None) call is meaningless; it only sets the baseline.
            self._ps.cpu_percent(interval=None)
        except Exception:  # noqa: BLE001 - priming must never break startup
            pass

    def _read_temperature(self) -> float | None:
        sensors = getattr(self._ps, "sensors_temperatures", None)  # Linux only
        if callable(sensors):
            try:
                data = sensors() or {}
            except Exception:  # noqa: BLE001
                data = {}
            ordered = [data[k] for k in _PREFERRED_SENSORS if data.get(k)]
            ordered += [v for k, v in data.items() if k not in _PREFERRED_SENSORS and v]
            for entries in ordered:
                temp = _plausible(float(entries[0].current))
                if temp is not None:
                    return temp
        try:  # Raspberry Pi fallback: millidegrees in sysfs, readable without root.
            return _plausible(int(self._thermal_path.read_text().strip()) / 1000.0)
        except (OSError, ValueError):
            return None

    def collect(self) -> CollectionResult[MetricsSample]:
        try:
            cpu = _clamp_pct(self._ps.cpu_percent(interval=None))
            memory = _clamp_pct(self._ps.virtual_memory().percent)
            disk = _clamp_pct(self._ps.disk_usage(self._disk_path).percent)
            uptime = max(0.0, self._clock() - float(self._ps.boot_time()))
            net = self._ps.net_io_counters()
            temperature = self._read_temperature()
        except Exception as exc:  # noqa: BLE001
            # Only the exception type is reported; messages can contain paths or usernames.
            status = make_status(NAME, CollectorState.ERROR, detail=type(exc).__name__)
            return CollectionResult[MetricsSample](status=status)

        missing: list[str] = []
        if temperature is None:
            missing.append("temperature_c")
        if net is None:
            missing += ["net_rx_bytes", "net_tx_bytes"]

        sample = MetricsSample(
            timestamp=utcnow(),
            cpu_percent=cpu,
            memory_percent=memory,
            disk_percent=disk,
            temperature_c=temperature,
            uptime_seconds=uptime,
            net_rx_bytes=int(net.bytes_recv) if net is not None else None,
            net_tx_bytes=int(net.bytes_sent) if net is not None else None,
        )
        detail = f"optional fields unavailable: {', '.join(missing)}" if missing else None
        return CollectionResult[MetricsSample](
            status=make_status(NAME, CollectorState.OK, detail=detail, missing=missing),
            data=sample,
        )
