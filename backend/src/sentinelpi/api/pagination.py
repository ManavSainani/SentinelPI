"""Opaque keyset cursors and the shared page envelope.

A cursor names the last row a client saw, so the next page continues exactly after it even if
new rows arrive meanwhile (offset paging would skip or repeat rows)."""

from __future__ import annotations

import base64
import binascii
import json
import re

from pydantic import BaseModel

from sentinelpi.api.errors import ApiError

_TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
_ID = re.compile(r"^[0-9a-f-]{1,40}$")


class Page(BaseModel):
    items: list
    total: int
    limit: int
    next_cursor: str | None = None


def encode_cursor(timestamp_db: str, row_id: str) -> str:
    raw = json.dumps([timestamp_db, row_id], separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_cursor(cursor: str | None) -> tuple[str, str] | None:
    if cursor is None:
        return None
    try:
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
        value = json.loads(raw)
        if (
            isinstance(value, list)
            and len(value) == 2
            and all(isinstance(v, str) for v in value)
            and _TS.match(value[0])
            and _ID.match(value[1])
        ):
            return value[0], value[1]
    except (binascii.Error, ValueError, UnicodeDecodeError):
        pass
    raise ApiError(400, "invalid_cursor", "The cursor is not valid. Start again without it.")
