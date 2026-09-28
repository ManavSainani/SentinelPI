import socket
import subprocess
from collections import namedtuple
from types import SimpleNamespace as NS

import psutil

from sentinelpi.collectors.base import CollectorState
from sentinelpi.collectors.ports import PortCollector, parse_lsof_fields

Addr = namedtuple("Addr", "ip port")
TCP, UDP = socket.SOCK_STREAM, socket.SOCK_DGRAM


def conn(type_, ip, port, status="LISTEN", raddr=(), pid=None):
    return NS(type=type_, laddr=Addr(ip, port), raddr=raddr, status=status, pid=pid)


def fake_ps(conns=None, error=None, names=None):
    names = names or {}

    def net_connections(kind="inet"):
        if error:
            raise error
        return conns

    def Process(pid):  # noqa: N802 - mirrors psutil API
        if pid not in names:
            raise psutil.NoSuchProcess(pid)
        return NS(name=lambda: names[pid])

    return NS(net_connections=net_connections, Process=Process)


LSOF = """p123
cpython3
f5
n127.0.0.1:8787
p456
crapportd
f4
n*:49152
f5
n[::1]:49152
f6
n10.0.0.2:51000->1.2.3.4:443
"""


def test_only_listening_sockets_are_kept():
    conns = [
        conn(TCP, "0.0.0.0", 22, pid=1),
        conn(TCP, "127.0.0.1", 5000, status="ESTABLISHED", raddr=Addr("1.1.1.1", 443)),
        conn(UDP, "0.0.0.0", 68, status="NONE", pid=2),
        conn(UDP, "10.0.0.2", 5555, status="NONE", raddr=Addr("8.8.8.8", 53)),  # connected UDP
    ]
    r = PortCollector(psutil_mod=fake_ps(conns, names={1: "sshd", 2: "dhcpcd"})).collect()
    assert r.status.state == CollectorState.OK
    got = [(p.protocol, p.port, p.process_name) for p in r.data.ports]
    assert got == [("tcp", 22, "sshd"), ("udp", 68, "dhcpcd")]


def test_duplicates_removed_and_sorted():
    conns = [
        conn(TCP, "::", 80, pid=1),
        conn(TCP, "::", 80, pid=1),
        conn(TCP, "0.0.0.0", 22, pid=1),
    ]
    r = PortCollector(psutil_mod=fake_ps(conns, names={1: "x"})).collect()
    assert [p.port for p in r.data.ports] == [22, 80]


def test_other_users_sockets_noted_not_fatal():
    r = PortCollector(psutil_mod=fake_ps([conn(TCP, "0.0.0.0", 631, pid=None)])).collect()
    assert r.status.state == CollectorState.OK
    assert "1 socket(s)" in r.status.detail
    assert r.data.ports[0].pid is None and r.data.ports[0].process_name is None


def test_process_vanishing_is_tolerated():
    r = PortCollector(psutil_mod=fake_ps([conn(TCP, "0.0.0.0", 22, pid=99)], names={})).collect()
    assert r.data.ports[0].pid == 99 and r.data.ports[0].process_name is None


def test_bounded():
    conns = [conn(TCP, "0.0.0.0", p, pid=None) for p in range(1000, 1010)]
    r = PortCollector(limit=4, psutil_mod=fake_ps(conns)).collect()
    assert len(r.data.ports) == 4 and r.data.total_count == 10 and r.data.truncated


def test_access_denied_uses_lsof_fallback_without_shell():
    seen = {}

    def runner(cmd, **kwargs):
        seen["cmd"], seen["kwargs"] = cmd, kwargs
        return NS(stdout=LSOF, returncode=0)

    ps = fake_ps(error=psutil.AccessDenied())
    r = PortCollector(psutil_mod=ps, runner=runner).collect()
    assert r.status.state == CollectorState.DEGRADED
    assert "udp" in r.status.missing
    assert isinstance(seen["cmd"], list) and not seen["kwargs"].get("shell")
    assert seen["kwargs"]["timeout"] > 0
    assert [(p.local_address, p.port, p.process_name) for p in r.data.ports] == [
        ("127.0.0.1", 8787, "python3"),
        ("*", 49152, "rapportd"),
        ("::1", 49152, "rapportd"),
    ]


def test_lsof_missing_is_unavailable_not_crash():
    def runner(cmd, **kwargs):
        raise FileNotFoundError

    r = PortCollector(psutil_mod=fake_ps(error=psutil.AccessDenied()), runner=runner).collect()
    assert r.status.state == CollectorState.UNAVAILABLE
    assert r.data is None


def test_lsof_timeout_is_unavailable():
    def runner(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd="lsof", timeout=5)

    r = PortCollector(psutil_mod=fake_ps(error=psutil.AccessDenied()), runner=runner).collect()
    assert r.status.state == CollectorState.UNAVAILABLE
    assert "TimeoutExpired" in r.status.detail


def test_unexpected_error_reports_type_only():
    r = PortCollector(psutil_mod=fake_ps(error=RuntimeError("/secret"))).collect()
    assert r.status.state == CollectorState.ERROR
    assert r.status.detail == "RuntimeError"


def test_lsof_parser_skips_connections_and_garbage():
    ports = parse_lsof_fields(LSOF + "nnotaport\nn*:99999\nn*:abc\n")
    assert len(ports) == 3  # the "->" line, bad port, and non-numeric port are ignored
