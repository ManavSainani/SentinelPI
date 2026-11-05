"""Request-level protections for a local, unauthenticated API.

* Host allowlist - stops DNS-rebinding (a web page reaching this API under another name).
* Same-origin check on state-changing requests - stops other web pages from making your
  browser acknowledge or resolve incidents (CSRF). Browsers always send Origin on these.
* JSON-only bodies - a cross-site form cannot send application/json without a CORS
  preflight, and no CORS is enabled.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from starlette.types import ASGIApp, Receive, Scope, Send

from sentinelpi.api.errors import error_response

_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


_HOST = re.compile(r"^(?:\[(?P<v6>[0-9a-f:.]+)\]|(?P<name>[a-z0-9.-]+))(?::\d{1,5})?$")


def _host_name(header: str) -> str:
    """The host name from a Host header, or '' if the header is not a plain host[:port]."""
    m = _HOST.match(header.strip().lower())
    return (m.group("v6") or m.group("name")) if m else ""


class SecurityMiddleware:
    def __init__(self, app: ASGIApp, allowed_hosts: list[str], allowed_origins: list[str]) -> None:
        self.app = app
        self.hosts = {h.strip().lower().strip("[]") for h in allowed_hosts}
        self.origins = {o.strip().lower().rstrip("/") for o in allowed_origins}

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope["headers"]}
        host_header = headers.get("host", "")
        problem: tuple[int, str, str] | None = None
        if _host_name(host_header) not in self.hosts:
            problem = (403, "forbidden_host", "This host name is not allowed.")
        elif scope["method"] not in _SAFE_METHODS:
            origin = headers.get("origin")
            if origin is not None and not self._origin_ok(origin, host_header):
                problem = (403, "forbidden_origin", "Cross-origin requests are not allowed.")
            elif not headers.get("content-type", "").lower().startswith("application/json"):
                problem = (415, "unsupported_media_type", "Send application/json.")
        if problem is not None:
            response = error_response(*problem)
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)

    def _origin_ok(self, origin: str, host_header: str) -> bool:
        origin = origin.strip().lower().rstrip("/")
        if origin in self.origins:
            return True
        return urlsplit(origin).netloc == host_header.strip().lower()
