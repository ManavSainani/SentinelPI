from __future__ import annotations

import logging
import time
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from sentinelpi import __version__
from sentinelpi.api import health
from sentinelpi.config import Settings, load_settings

log = logging.getLogger("sentinelpi")


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()
    app = FastAPI(title="SentinelPi", version=__version__)
    app.state.settings = settings
    app.state.started_at = time.time()
    if settings.exposes_lan:
        log.warning(
            "SentinelPi is bound to %s (not loopback). The API has no authentication yet.",
            settings.server.host,
        )
    app.include_router(health.router, prefix="/api")

    # Serve the built dashboard if it exists. Mounted last so /api/* keeps priority.
    dist = Path(settings.frontend_dist)
    if (dist / "index.html").is_file():
        app.mount("/", StaticFiles(directory=dist, html=True), name="frontend")
    else:
        log.info("No built frontend at %s; API only (use `npm run dev` for the UI).", dist)
    return app


def run() -> None:
    import uvicorn

    s = load_settings()
    uvicorn.run(create_app(s), host=s.server.host, port=s.server.port)


if __name__ == "__main__":
    run()
