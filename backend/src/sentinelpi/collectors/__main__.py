"""Live check: `python -m sentinelpi.collectors [metrics|processes|ports]`.

Prints one telemetry snapshot as JSON so you can verify collectors on a real host
without the API or a database.
"""

from __future__ import annotations

import sys
import time

from sentinelpi.collectors import HostCollectors
from sentinelpi.config import load_settings


def main(argv: list[str]) -> int:
    which = argv[0] if argv else "all"
    if which not in {"all", "metrics", "processes", "ports"}:
        print("usage: python -m sentinelpi.collectors [metrics|processes|ports]", file=sys.stderr)
        return 2
    collectors = HostCollectors(load_settings().collection)
    time.sleep(1.0)  # let CPU counters accumulate so the first reading means something
    telemetry = collectors.collect_all()
    if which == "all":
        print(telemetry.model_dump_json(indent=2))
    else:
        print(getattr(telemetry, which).model_dump_json(indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
