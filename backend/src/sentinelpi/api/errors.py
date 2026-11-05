"""One error shape for every failure: {"error": {"code", "message", "details"?}}.

Messages never echo request values or internal exception text, so a failure cannot leak a
path, a SQL fragment or a secret."""

from __future__ import annotations

import logging
import sqlite3
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

log = logging.getLogger("sentinelpi.api")

_STATUS_CODES = {
    400: "bad_request",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    409: "conflict",
    415: "unsupported_media_type",
    422: "validation_error",
    503: "service_unavailable",
}


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


def error_response(status: int, code: str, message: str, details: Any = None) -> JSONResponse:
    body: dict[str, Any] = {"error": {"code": code, "message": message}}
    if details is not None:
        body["error"]["details"] = details
    return JSONResponse(status_code=status, content=body)


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(ApiError)
    async def _api_error(_: Request, exc: ApiError) -> JSONResponse:
        return error_response(exc.status, exc.code, exc.message)

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = _STATUS_CODES.get(exc.status_code, "error")
        message = {404: "Not found.", 405: "Method not allowed."}.get(
            exc.status_code, "Request could not be completed."
        )
        return error_response(exc.status_code, code, message)

    @app.exception_handler(RequestValidationError)
    async def _validation(_: Request, exc: RequestValidationError) -> JSONResponse:
        # Field locations and rule names only: never the submitted values.
        details = [
            {"field": ".".join(str(p) for p in e["loc"] if p != "query"), "problem": e["type"]}
            for e in exc.errors()[:20]
        ]
        return error_response(422, "validation_error", "Invalid request.", details)

    @app.exception_handler(sqlite3.Error)
    async def _database(_: Request, exc: sqlite3.Error) -> JSONResponse:
        log.error("database error: %s", type(exc).__name__)
        return error_response(503, "database_unavailable", "The database is not available.")

    @app.exception_handler(Exception)
    async def _unexpected(_: Request, exc: Exception) -> JSONResponse:
        log.error("unexpected error: %s", type(exc).__name__)
        return error_response(500, "internal_error", "Unexpected error.")
