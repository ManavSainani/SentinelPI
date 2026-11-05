from __future__ import annotations

import logging
import time
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from sentinelpi import __version__
from sentinelpi.api import events, health, incidents, rules, system, telemetry
from sentinelpi.api.errors import install_error_handlers
from sentinelpi.api.security import SecurityMiddleware
from sentinelpi.config import Settings, load_settings
from sentinelpi.storage.db import Database

log = logging.getLogger("sentinelpi")


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()
    # The interactive docs list every route; keep them to a local-only server.
    docs = not settings.exposes_lan
    app = FastAPI(
        title="SentinelPi",
        version=__version__,
        docs_url="/api/docs" if docs else None,
        redoc_url=None,
        openapi_url="/api/openapi.json" if docs else None,
    )
    app.state.settings = settings
    app.state.db = Database(settings.storage.db_path)
    install_error_handlers(app)
    app.add_middleware(
        SecurityMiddleware,
        allowed_hosts=settings.server.allowed_hosts,
        allowed_origins=settings.server.allowed_origins,
    )
    app.state.started_at = time.time()
    if settings.exposes_lan:
        log.warning(
            "SentinelPi is bound to %s (not loopback). The API has no authentication yet.",
            settings.server.host,
        )
    app.include_router(health.router, prefix="/api")  # kept for the dashboard shell
    app.include_router(health.router, prefix="/api/v1")
    for router in (
        system.router,
        events.router,
        incidents.router,
        telemetry.router,
        rules.router,
    ):
        app.include_router(router, prefix="/api/v1")

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
    Database(s.storage.db_path).migrate()  # the API never serves a half-created database
    uvicorn.run(create_app(s), host=s.server.host, port=s.server.port)


if __name__ == "__main__":
    run()
