"""End-to-end verification and measurement (Phase 9).

    python -m sentinelpi.verify demo            # controlled attack -> incident -> API -> ack
    python -m sentinelpi.verify bench           # idle resource use, DB growth, API latency

Both start the real monitor and the real API as separate processes inside a throwaway
directory (their own database, config and fake auth log), so nothing touches your real data
and the run is repeatable. All attack traffic is synthetic: documentation-range IPs written
to a temporary log file, plus a harmless copy of `sleep` named `nc`.

This is an explicit development command; the application itself never generates test events.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

import psutil

ATTACKER_IP = "203.0.113.77"  # RFC 5737 documentation range: never routable
FAILED_ATTEMPTS = 8


# ---------------------------------------------------------------- stack lifecycle


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _repo_dist() -> str:
    for parent in Path(__file__).resolve().parents:
        if (parent / "frontend" / "dist" / "index.html").is_file():
            return str(parent / "frontend" / "dist")
    return "frontend/dist"


class Stack:
    """A private monitor + API pair running in a temporary directory."""

    def __init__(self, workdir: Path, *, fast: bool = True) -> None:
        self.dir = workdir
        self.port = _free_port()
        self.base = f"http://127.0.0.1:{self.port}"
        self.auth_log = workdir / "auth.log"
        self.db_path = workdir / "data" / "verify.db"
        self.config = workdir / "config.toml"
        self.procs: dict[str, subprocess.Popen[bytes]] = {}
        self.fast = fast
        self.bin = workdir / "bin"

    def write_config(self) -> None:
        (self.dir / "data").mkdir(exist_ok=True)
        self.auth_log.write_text("")
        iv = (2, 10, 5, 5) if self.fast else (10, 60, 15, 30)
        self.config.write_text(
            f'frontend_dist = "{_repo_dist()}"\n'
            f"[server]\nport = {self.port}\n"
            f'[storage]\ndb_path = "{self.db_path}"\n'
            f'[auth]\nauth_log_paths = ["{self.auth_log}"]\ninitial_lookback_minutes = 15\n'
            f"[monitor]\nmetrics_interval_seconds = {iv[0]}\n"
            f"snapshot_interval_seconds = {iv[1]}\nauth_interval_seconds = {iv[2]}\n"
            f"detection_interval_seconds = {iv[3]}\nretention_interval_seconds = 3600\n"
            '[detection.watchlist]\nprocess_names = ["nc"]\n'
        )

    def _env(self) -> dict[str, str]:
        # An empty PATH hides journalctl so the monitor reads the fake log file, even on a
        # Pi whose real SSH events live in the systemd journal.
        self.bin.mkdir(exist_ok=True)
        env = {"SENTINELPI_CONFIG": str(self.config), "PATH": str(self.bin), "LC_ALL": "C"}
        if "TZ" in os.environ:  # the fake log uses local time; keep the children in the same zone
            env["TZ"] = os.environ["TZ"]
        return env

    def start(self) -> None:
        self.write_config()
        env = self._env()
        for name, module in (("monitor", "sentinelpi.monitor"), ("api", "sentinelpi.main")):
            log = open(self.dir / f"{name}.log", "wb")  # noqa: SIM115 - closed by the OS on exit
            self.procs[name] = subprocess.Popen(
                [sys.executable, "-m", module],
                env=env,
                stdout=log,
                stderr=subprocess.STDOUT,
                cwd=self.dir,
            )
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            for name, p in self.procs.items():
                if p.poll() is not None:
                    raise RuntimeError(f"{name} exited early; see {self.dir / (name + '.log')}")
            try:
                if http("GET", f"{self.base}/api/v1/health")[0] == 200:
                    return
            except OSError:
                pass
            time.sleep(0.3)
        raise RuntimeError("the API did not become healthy within 30 seconds")

    def stop(self) -> None:
        for p in self.procs.values():
            if p.poll() is None:
                p.terminate()
        for p in self.procs.values():
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()

    def url(self, path: str) -> str:
        return f"{self.base}/api/v1{path}"


def http(method: str, url: str, body: dict[str, Any] | None = None) -> tuple[int, Any]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read() or b"null")
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read() or b"null")
        except ValueError:
            return exc.code, None


def wait_for(fn: Callable[[], Any], timeout: float, interval: float = 0.5) -> Any:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = fn()
        if value:
            return value
        time.sleep(interval)
    return None


# ---------------------------------------------------------------- attack generators


def _stamp(now: datetime) -> str:
    return f"{now:%b} {now.day:>2} {now:%H:%M:%S}"


def write_ssh_attack(log: Path, count: int = FAILED_ATTEMPTS) -> None:
    now = datetime.now().astimezone()
    host = platform.node() or "host"
    lines = [
        f"{_stamp(now)} {host} sshd[{4000 + i}]: Failed password for invalid user admin "
        f"from {ATTACKER_IP} port {50000 + i} ssh2\n"
        for i in range(count)
    ]
    with log.open("a") as fh:
        fh.writelines(lines)


def start_decoy_process(stack: Stack) -> subprocess.Popen[bytes]:
    """A harmless `sleep` copied under the watchlisted name `nc`."""
    sleep = shutil.which("sleep") or "/bin/sleep"
    nc = stack.bin / "nc"
    stack.bin.mkdir(exist_ok=True)
    shutil.copy2(sleep, nc)
    return subprocess.Popen([str(nc), "600"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


# ---------------------------------------------------------------- demo


class Report:
    def __init__(self) -> None:
        self.rows: list[tuple[str, bool, str]] = []

    def check(self, name: str, ok: bool, detail: str = "") -> bool:
        self.rows.append((name, ok, detail))
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""))
        return ok

    @property
    def passed(self) -> bool:
        return all(ok for _, ok, _ in self.rows)


def run_demo(keep: bool = False) -> int:
    report = Report()
    tmp = Path(tempfile.mkdtemp(prefix="sentinelpi-demo."))
    stack = Stack(tmp)
    decoy: subprocess.Popen[bytes] | None = None
    listener: socket.socket | None = None
    print(f"Demo workspace: {tmp}\nStarting monitor and API on port {stack.port} ...")
    try:
        stack.start()
        t0 = time.monotonic()

        def status() -> dict[str, Any] | None:
            code, body = http("GET", stack.url("/system/status"))
            return body if code == 200 else None

        st = wait_for(lambda: (s := status()) and s["metrics"] and s, 30)
        report.check(
            "monitor collects metrics and heartbeats", bool(st and st["monitor"]["running"])
        )
        report.check("starts with no active alert", bool(st) and st["active_alert"] is None)

        print(f"\nInjecting {FAILED_ATTEMPTS} failed SSH logins from {ATTACKER_IP} ...")
        write_ssh_attack(stack.auth_log)
        t_attack = time.monotonic()

        def events(**q: str) -> list[dict[str, Any]]:
            qs = "&".join(f"{k}={v}" for k, v in {"limit": "200", **q}.items())
            code, body = http("GET", stack.url(f"/events?{qs}"))
            return body["items"] if code == 200 else []

        fails = wait_for(
            lambda: (e := [x for x in events() if x["event_type"] == "auth.ssh_failed_login"])
            and len(e) >= FAILED_ATTEMPTS
            and e,
            40,
        )
        report.check(
            "collector -> events: failed logins stored",
            bool(fails),
            f"{len(fails or [])} events",
        )
        report.check(
            "events carry the source IP; a made-up username is not stored",
            bool(fails)
            and all(e["source_ip"] == ATTACKER_IP and e["username"] is None for e in fails)
            and "admin" not in json.dumps(fails),
        )

        det = wait_for(
            lambda: [
                x
                for x in events()
                if x["event_type"].startswith("detection.") and "SP-001" in x["summary"]
            ],
            40,
        )
        report.check("events -> detection: SP-001 fired", bool(det))

        def active() -> dict[str, Any] | None:
            s = status()
            return s["active_alert"] if s else None

        alert = wait_for(active, 40)
        t_alert = time.monotonic() - t_attack
        report.check(
            "detection -> incident: High alert visible in /system/status",
            bool(alert) and alert["severity"] in ("high", "critical"),
            f"{t_alert:.1f}s after the attack was written",
        )
        incident_id = alert["id"] if alert else None
        if incident_id:
            code, inc = http("GET", stack.url(f"/incidents/{incident_id}"))
            report.check(
                "incident detail has evidence and a timeline", code == 200 and bool(inc["timeline"])
            )
            report.check("incident names the attacker IP", inc.get("source_ip") == ATTACKER_IP)

        print(
            "\nApproving a port baseline, then adding a decoy 'nc' (SP-004)"
            " and a new port (SP-002) ..."
        )
        base = subprocess.run(
            [sys.executable, "-m", "sentinelpi.detection", "baseline", "capture", "--yes"],
            env=stack._env(),
            cwd=stack.dir,
            capture_output=True,
            text=True,
            timeout=60,
        )
        report.check("port baseline captured", base.returncode == 0, base.stderr.strip()[:120])
        decoy = start_decoy_process(stack)
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        # The SSH attack and these two host-level signals are separate incidents by design:
        # an attacker IP is a different subject from "something odd on this host".

        def escalated() -> dict[str, Any] | None:
            code, page = http("GET", stack.url("/incidents?limit=50"))
            if code != 200:
                return None
            for i in page["items"]:
                if {"SP-002", "SP-004"} <= set(i["rule_ids"]):
                    return i  # type: ignore[no-any-return]
            return None

        esc = wait_for(escalated, 60)
        report.check(
            "two host-level rules join one incident and SP-005 escalates it",
            bool(esc),
            f"rules: {', '.join(esc['rule_ids'])}" if esc else "no combined incident",
        )
        if esc:
            code, detail = http("GET", stack.url(f"/incidents/{esc['id']}"))
            audit = [t.get("audit_kind") for t in detail.get("timeline", [])]
            report.check(
                "SP-005 raised two Medium rules to High, with an audit entry",
                esc["severity"] in ("high", "critical") and "escalated" in audit,
                f"severity {esc['severity']}",
            )

        if incident_id:
            code, _ = http(
                "PATCH", stack.url(f"/incidents/{incident_id}"), {"status": "acknowledged"}
            )
            report.check("acknowledge via API", code == 200)
            code, _ = http(
                "PATCH",
                stack.url(f"/incidents/{incident_id}"),
                {"status": "resolved", "note": "demo"},
            )
            report.check("resolve via API", code == 200)
            code, body = http(
                "PATCH", stack.url(f"/incidents/{incident_id}"), {"status": "acknowledged"}
            )
            report.check(
                "reopening a resolved incident is refused with 409", code == 409, f"HTTP {code}"
            )
            code, inc = http("GET", stack.url(f"/incidents/{incident_id}"))
            kinds = [t["audit_kind"] for t in inc["timeline"] if t["kind"] == "audit"]
            report.check(
                "audit trail records the whole lifecycle",
                "created" in kinds and "status_changed" in kinds,
            )

        code, body = http("GET", stack.url("/system/status"))
        report.check("API still healthy at the end", code == 200)
        mon_log = (tmp / "monitor.log").read_text(errors="replace")
        report.check("monitor log has no tracebacks", "Traceback" not in mon_log)
        api_log = (tmp / "api.log").read_text(errors="replace")
        report.check("API log has no tracebacks", "Traceback" not in api_log)
        print(f"\nTotal demo time: {time.monotonic() - t0:.0f}s")
    except Exception as exc:  # noqa: BLE001 - report any failure as a failed demo
        report.check("demo ran to completion", False, f"{type(exc).__name__}: {exc}")
    finally:
        if decoy is not None:
            decoy.terminate()
        if listener is not None:
            listener.close()
        stack.stop()
        if not keep:
            shutil.rmtree(tmp, ignore_errors=True)
    print(
        "\nRESULT:",
        "PASS" if report.passed else "FAIL",
        f"({sum(ok for _, ok, _ in report.rows)}/{len(report.rows)} checks)",
    )
    return 0 if report.passed else 1


# ---------------------------------------------------------------- benchmark


def _percentile(values: list[float], pct: float) -> float:
    ordered = sorted(values)
    k = (len(ordered) - 1) * pct / 100
    lo, hi = int(k), min(int(k) + 1, len(ordered) - 1)
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (k - lo)


def _host_context() -> dict[str, Any]:
    model = None
    try:
        model = Path("/proc/device-tree/model").read_text().strip("\x00\n ")
    except OSError:
        pass
    return {
        "machine": model or platform.machine(),
        "os": f"{platform.system()} {platform.release()}",
        "python": platform.python_version(),
        "cpu_count": psutil.cpu_count(),
        "ram_mb": round(psutil.virtual_memory().total / 1e6),
        "measured_at": datetime.now().astimezone().isoformat(timespec="seconds"),
    }


def _proc_sample(p: psutil.Process) -> dict[str, float]:
    io = p.io_counters() if hasattr(p, "io_counters") else None
    return {
        "cpu_time": sum(p.cpu_times()[:2]),
        "rss": float(p.memory_info().rss),
        "write_bytes": float(getattr(io, "write_bytes", 0)) if io else 0.0,
    }


def run_bench(idle_seconds: int, requests: int, realistic: bool, output: str | None) -> int:
    tmp = Path(tempfile.mkdtemp(prefix="sentinelpi-bench."))
    # Realistic intervals by default (10 s metrics) so the numbers describe real use.
    stack = Stack(tmp, fast=not realistic)
    try:
        stack.start()
        procs = {n: psutil.Process(p.pid) for n, p in stack.procs.items()}
        print(f"Warm-up 15 s, then measuring {idle_seconds} s idle ...")
        time.sleep(15)
        db_files = lambda: sum(  # noqa: E731
            f.stat().st_size
            for f in stack.db_path.parent.glob(stack.db_path.name + "*")
            if f.is_file()
        )
        before = {n: _proc_sample(p) for n, p in procs.items()}
        db0, t0 = db_files(), time.monotonic()
        rss_peak = {n: before[n]["rss"] for n in procs}
        while time.monotonic() - t0 < idle_seconds:
            time.sleep(2)
            for n, p in procs.items():
                rss_peak[n] = max(rss_peak[n], p.memory_info().rss)
        elapsed = time.monotonic() - t0
        after = {n: _proc_sample(p) for n, p in procs.items()}
        idle = {
            n: {
                "cpu_percent_of_one_core": round(
                    (after[n]["cpu_time"] - before[n]["cpu_time"]) / elapsed * 100, 2
                ),
                "rss_mb": round(after[n]["rss"] / 1e6, 1),
                "rss_peak_mb": round(rss_peak[n] / 1e6, 1),
                "disk_written_kb_per_min": round(
                    (after[n]["write_bytes"] - before[n]["write_bytes"]) / 1024 / elapsed * 60, 1
                ),
            }
            for n in procs
        }
        db_growth_kb_per_hour = round((db_files() - db0) / 1024 / elapsed * 3600, 1)

        # Put some data in so list routes do real work, then time the common routes.
        write_ssh_attack(stack.auth_log, 40)
        time.sleep(8 if not realistic else 20)
        routes = [
            "/health",
            "/system/status",
            "/events?limit=50",
            "/incidents?limit=50",
            "/system/metrics",
            "/network/listeners",
        ]
        latency: dict[str, dict[str, float]] = {}
        for route in routes:
            samples: list[float] = []
            for _ in range(requests):
                s = time.perf_counter()
                code, _ = http("GET", stack.url(route))
                samples.append((time.perf_counter() - s) * 1000)
                if code != 200:
                    raise RuntimeError(f"{route} returned HTTP {code}")
            latency[route] = {
                "p50_ms": round(_percentile(samples, 50), 1),
                "p95_ms": round(_percentile(samples, 95), 1),
                "max_ms": round(max(samples), 1),
            }
        result = {
            "host": _host_context(),
            "method": {
                "intervals": "default (10 s metrics, 60 s snapshots)"
                if realistic
                else "fast demo intervals",
                "idle_seconds": idle_seconds,
                "requests_per_route": requests,
                "note": "monitor and API measured as separate processes; sequential local requests",
            },
            "idle": idle,
            "database_growth_kb_per_hour_idle": db_growth_kb_per_hour,
            "api_latency": latency,
        }
        print(json.dumps(result, indent=2))
        if output:
            Path(output).write_text(json.dumps(result, indent=2) + "\n")
            print(f"\nSaved to {output}")
        return 0
    except Exception as exc:  # noqa: BLE001
        print(f"Benchmark failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    finally:
        stack.stop()
        shutil.rmtree(tmp, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m sentinelpi.verify")
    sub = parser.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("demo", help="controlled end-to-end demo with pass/fail checks")
    d.add_argument("--keep", action="store_true", help="keep the temporary workspace")
    b = sub.add_parser("bench", help="measure resource use and API latency")
    b.add_argument("--idle-seconds", type=int, default=120)
    b.add_argument("--requests", type=int, default=100)
    b.add_argument("--fast-intervals", action="store_true", help="use fast demo intervals")
    b.add_argument("--output", help="write the results as JSON to this file")
    args = parser.parse_args(argv)
    if args.cmd == "demo":
        return run_demo(args.keep)
    return run_bench(args.idle_seconds, args.requests, not args.fast_intervals, args.output)


if __name__ == "__main__":
    os.environ.setdefault("PYTHONUNBUFFERED", "1")
    raise SystemExit(main())
