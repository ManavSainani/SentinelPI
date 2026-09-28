from __future__ import annotations

import platform
import time

from fastapi import APIRouter, Request

from sentinelpi import __version__

router = APIRouter()


@router.get("/health")
def health(request: Request) -> dict:
    started: float = request.app.state.started_at
    return {
        "status": "ok",
        "version": __version__,
        "uptime_seconds": round(time.time() - started, 1),
        "platform": platform.system().lower(),
        "arch": platform.machine(),
        "python": platform.python_version(),
    }
