from types import SimpleNamespace as NS

from sentinelpi.collectors.base import CollectorState
from sentinelpi.collectors.processes import ProcessCollector


def proc(pid, name="x", cpu=0.0, mem=0.0, user="pi"):
    return NS(
        info={
            "pid": pid,
            "name": name,
            "username": user,
            "cpu_percent": cpu,
            "memory_percent": mem,
        }
    )


def fake_ps(procs, calls=None, fail_first=False):
    state = {"n": 0}

    def process_iter(attrs=None):
        if calls is not None:
            calls.append(list(attrs or []))
        state["n"] += 1
        if fail_first and state["n"] == 1:
            raise RuntimeError("prime failed")
        return list(procs)

    return NS(process_iter=process_iter)


def test_sorted_by_load_and_bounded():
    procs = [proc(i, cpu=float(i), mem=1.0) for i in range(1, 6)]
    r = ProcessCollector(limit=3, psutil_mod=fake_ps(procs)).collect()
    assert r.status.state == CollectorState.OK
    assert [p.pid for p in r.data.processes] == [5, 4, 3]
    assert r.data.total_count == 5
    assert r.data.truncated is True


def test_never_requests_sensitive_attributes():
    calls = []
    ProcessCollector(limit=5, psutil_mod=fake_ps([proc(1)], calls)).collect()
    requested = {a for call in calls for a in call}
    assert requested.isdisjoint({"cmdline", "environ", "exe", "cwd", "open_files", "connections"})


def test_restricted_fields_do_not_break_collection():
    restricted = NS(
        info={"pid": 9, "name": None, "username": None, "cpu_percent": None, "memory_percent": None}
    )
    r = ProcessCollector(psutil_mod=fake_ps([restricted, proc(1)])).collect()
    assert r.status.state == CollectorState.OK
    assert "1 process(es)" in r.status.detail
    unknown = next(p for p in r.data.processes if p.pid == 9)
    assert unknown.name == "<unknown>" and unknown.cpu_percent == 0.0


def test_names_are_sanitized_and_truncated():
    weird = proc(1, name="ev\x1b[31mil" + "a" * 200)
    r = ProcessCollector(psutil_mod=fake_ps([weird])).collect()
    name = r.data.processes[0].name
    assert "\x1b" not in name and len(name) <= 64
    assert r.data.processes[0].command_redacted == name


def test_priming_failure_is_tolerated():
    c = ProcessCollector(psutil_mod=fake_ps([proc(1)], fail_first=True))
    assert c.collect().status.state == CollectorState.OK


def test_iteration_error_reports_type_only():
    def process_iter(attrs=None):
        raise OSError("/proc/secret")

    r = ProcessCollector(psutil_mod=NS(process_iter=process_iter)).collect()
    assert r.status.state == CollectorState.ERROR
    assert r.status.detail == "OSError"
