"""Live check: `python -m sentinelpi.collectors [metrics|processes|ports|auth]`.

Prints one telemetry snapshot as JSON so you can verify collectors on a real host
without the API or a database. `auth` is a dry run: it prints parsed
SSH events but stores nothing and saves no cursor.
"""

from __future__ import annotations

import sys
import time

from sentinelpi.collectors import HostCollectors
from sentinelpi.collectors.auth_logs import build_auth_collector
from sentinelpi.config import load_settings


def main(argv: list[str]) -> int:
    which = argv[0] if argv else "all"
    if which not in {"all", "metrics", "processes", "ports", "auth"}:
        print(
            "usage: python -m sentinelpi.collectors [metrics|processes|ports|auth]",
            file=sys.stderr,
        )
        return 2
    settings = load_settings()
    if which == "auth":
        print(build_auth_collector(settings.auth).poll({}).result.model_dump_json(indent=2))
        return 0
    collectors = HostCollectors(settings.collection)
    time.sleep(1.0)  # let CPU counters accumulate so the first reading means something
    telemetry = collectors.collect_all()
    if which == "all":
        print(telemetry.model_dump_json(indent=2))
    else:
        print(getattr(telemetry, which).model_dump_json(indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
