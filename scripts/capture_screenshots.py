#!/usr/bin/env python3
"""Capture the README screenshots from a private demo stack (synthetic data only).

    cd backend && ../.venv/bin/python ../scripts/capture_screenshots.py --out ../docs/img

Needs `make build` first, and Playwright with Chromium for the interpreter named by
--browser-python (default: python3). The stack is the same one `sentinelpi.verify demo` uses:
a temporary database, a fake auth log and documentation-range IP addresses.
"""

from __future__ import annotations

import argparse
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from sentinelpi.verify import Stack, http, start_decoy_process, wait_for, write_ssh_attack

SHOOT = r"""
import sys
from playwright.sync_api import sync_playwright
base, out, group = sys.argv[1], sys.argv[2], sys.argv[3]
inc = sys.argv[4] if len(sys.argv) > 4 else ""
calm = [("overview-light", "#/", 1280, 820, "light", True),
        ("overview-dark", "#/", 1280, 820, "dark", True),
        ("kiosk-calm", "#/kiosk", 1280, 720, "dark", False)]
alert = [("kiosk-alert", "#/kiosk", 1280, 720, "dark", False),
         ("incidents", "#/incidents", 1280, 640, "dark", False),
         ("incident-detail", "#/incidents/" + inc, 1280, 1000, "dark", False),
         ("network", "#/network", 1280, 640, "dark", False),
         ("phone", "#/", 390, 844, "dark", False)]
with sync_playwright() as p:
    b = p.chromium.launch()
    for name, route, w, h, scheme, _ in (calm if group == "calm" else alert):
        pg = b.new_page(viewport={"width": w, "height": h}, color_scheme=scheme)
        pg.goto(base + route)
        pg.wait_for_timeout(3000)
        pg.screenshot(path=f"{out}/{name}.png")
        pg.close()
    b.close()
"""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--browser-python", default="python3")
    ap.add_argument("--warmup", type=int, default=60, help="seconds of history before shooting")
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    work = Path(tempfile.mkdtemp(prefix="sentinelpi-shots."))
    stack = Stack(work)
    decoy = None
    listener = socket.socket()
    try:
        stack.start()
        print(f"collecting {args.warmup}s of history ...")
        time.sleep(args.warmup)

        def shoot(group: str, *extra: str) -> None:
            subprocess.run(
                [args.browser_python, "-c", SHOOT, stack.base + "/", str(args.out), group, *extra],
                check=True,
            )

        shoot("calm")
        write_ssh_attack(stack.auth_log)
        subprocess.run(
            [sys.executable, "-m", "sentinelpi.detection", "baseline", "capture", "--yes"],
            env=stack._env(),
            cwd=stack.dir,
            check=True,
            capture_output=True,
        )
        decoy = start_decoy_process(stack)
        listener.bind(("127.0.0.1", 0))
        listener.listen()

        def ready() -> str | None:
            items = http("GET", stack.url("/incidents?limit=20"))[1]["items"]
            ssh = [i for i in items if i["source_ip"]]
            host = [i for i in items if {"SP-002", "SP-004"} <= set(i["rule_ids"])]
            return ssh[0]["id"] if ssh and host else None

        incident = wait_for(ready, 90)
        if not incident:
            raise SystemExit("the demo incidents did not appear in time")
        time.sleep(6)
        shoot("alert", incident)
        print(f"screenshots written to {args.out}")
        return 0
    finally:
        if decoy is not None:
            decoy.terminate()
        listener.close()
        stack.stop()


if __name__ == "__main__":
    raise SystemExit(main())
