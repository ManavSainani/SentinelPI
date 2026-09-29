"""Sanitization and best-effort secret redaction for anything persisted or returned.

This is defense in depth, not a guarantee: patterns catch common leaks (password=..., bearer
tokens, private keys) but cannot recognize every secret. The real protection is to never
collect secrets in the first place (e.g. command-line arguments are never read).
"""

from __future__ import annotations

import json
import math
import re
from typing import Any

REDACTED = "[REDACTED]"

MAX_METADATA_BYTES = 4096
MAX_METADATA_KEYS = 50
MAX_METADATA_DEPTH = 3
MAX_LIST_ITEMS = 50
MAX_STRING_VALUE = 256

_KEY_OK = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")
# Values under keys containing these words are always replaced. Name harmless counters
# differently (e.g. "failure_count", not "password_failures").
_SECRET_KEY = re.compile(
    r"(passwords?|passwd|pwd|secret|token|api[_-]?key|private[_-]?key|cookie"
    r"|session[_-]?id|authorization|credentials?)",
    re.IGNORECASE,
)
_TEXT_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"(-----BEGIN [A-Z ]*PRIVATE KEY-----).*?(-----END [A-Z ]*PRIVATE KEY-----|$)", re.S
        ),
        "[REDACTED PRIVATE KEY]",
    ),
    (re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE), "Bearer [REDACTED]"),
    (
        re.compile(r"\b(passwords?|passwd|pwd|secret|token|api[_-]?key)\b(\s*[=:]\s*)\S+", re.I),
        r"\1\2[REDACTED]",
    ),
]


def redact_text(value: str) -> str:
    for pattern, replacement in _TEXT_PATTERNS:
        value = pattern.sub(replacement, value)
    return value


def clean_text(value: str, max_len: int) -> str:
    """Redact, collapse to a single printable line, and truncate.

    Log-derived strings (usernames, process names) are attacker-controlled, so control
    characters and newlines (log-injection) are removed here.
    """
    single_line = " ".join(redact_text(value).split())
    printable = "".join(ch for ch in single_line if ch.isprintable())
    return printable[:max_len]


def _clean_value(value: Any, depth: int) -> Any:
    if value is None or isinstance(value, bool | int):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, str):
        return clean_text(value, MAX_STRING_VALUE)
    if isinstance(value, list | tuple):
        if depth >= MAX_METADATA_DEPTH:
            raise ValueError("metadata nested too deeply")
        return [_clean_value(v, depth + 1) for v in list(value)[:MAX_LIST_ITEMS]]
    if isinstance(value, dict):
        return _clean_dict(value, depth + 1)
    raise ValueError(f"unsupported metadata value type: {type(value).__name__}")


def _clean_dict(data: dict[Any, Any], depth: int) -> dict[str, Any]:
    if depth > MAX_METADATA_DEPTH:
        raise ValueError("metadata nested too deeply")
    if len(data) > MAX_METADATA_KEYS:
        raise ValueError(f"metadata has more than {MAX_METADATA_KEYS} keys")
    out: dict[str, Any] = {}
    for key, value in data.items():
        if not isinstance(key, str) or not _KEY_OK.match(key):
            raise ValueError("invalid metadata key")
        out[key] = REDACTED if _SECRET_KEY.search(key) else _clean_value(value, depth)
    return out


def sanitize_metadata(data: dict[str, Any]) -> dict[str, Any]:
    """Validate and redact event metadata. Raises ValueError for malformed input."""
    cleaned = _clean_dict(data, 1)
    size = len(json.dumps(cleaned, separators=(",", ":")).encode())
    if size > MAX_METADATA_BYTES:
        raise ValueError(f"metadata too large ({size} bytes; max {MAX_METADATA_BYTES})")
    return cleaned
