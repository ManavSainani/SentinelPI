"""Process-name watchlist matching, shared by the collector and the detection rule.

Linux truncates process names to 15 characters (`comm`), so a watchlist entry longer than
that is also matched by its 15-character prefix. Matching is case-insensitive and exact
(never substring), so watching "nc" does not flag "sync" or "ncdu".
"""

from __future__ import annotations

from collections.abc import Iterable

_COMM_MAX = 15


def normalize_watchlist(names: Iterable[str]) -> frozenset[str]:
    out: set[str] = set()
    for raw in names:
        name = raw.strip().lower()
        if not name:
            continue
        out.add(name)
        if len(name) > _COMM_MAX:
            out.add(name[:_COMM_MAX])
    return frozenset(out)


def is_watchlisted(process_name: str, watch: frozenset[str]) -> bool:
    return bool(watch) and process_name.strip().lower() in watch
