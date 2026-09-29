import contextlib
import time
from datetime import UTC, datetime

import pytest

from sentinelpi.collectors.auth_parser import (
    MalformedAuthLine,
    RawAuthEntry,
    local_user_exists,
    parse_ssh_message,
)
from sentinelpi.events import EventSource, Severity

TS = datetime(2026, 9, 28, 19, 20, 40, tzinfo=UTC)
KNOWN = {"msainani", "root"}


def exists(name):
    return name in KNOWN


def entry(msg, eid="cur-1", source="journal"):
    return RawAuthEntry(eid, TS, "manavpi", msg, source)


def parse(msg, **kw):
    return parse_ssh_message(entry(msg, **kw), exists)


@pytest.mark.parametrize(
    "msg",
    [
        "Server listening on 0.0.0.0 port 22.",
        "Connection closed by invalid user oracle 203.0.113.9 port 40001 [preauth]",
        "Received disconnect from 203.0.113.9 port 5: 11: Bye Bye [preauth]",
        "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh "
        "ruser= rhost=203.0.113.5  user=root",
        "Failed none for invalid user x from 203.0.113.9 port 1 ssh2",
        "",
        "totally unrelated text",
        "Failed password for root from 203.0.113.5 port 22 ssh2 " + "x" * 2000,  # over length cap
    ],
)
def test_irrelevant_lines_are_ignored(msg):
    assert parse(msg) is None


def test_failed_login_for_real_account():
    e = parse("Failed password for msainani from 192.168.1.20 port 51234 ssh2")
    assert e.event_type == "auth.ssh_failed_login" and e.severity == Severity.LOW
    assert e.source == EventSource.AUTH_LOG and e.process_name == "sshd" and e.host == "manavpi"
    assert e.username == "msainani" and e.source_ip == "192.168.1.20"
    assert e.summary == "Failed SSH login for msainani from 192.168.1.20"
    assert e.metadata == {
        "user_exists": True,
        "log_source": "journal",
        "src_port": 51234,
        "auth_method": "password",
    }


def test_unknown_user_is_never_stored_or_echoed():
    # Someone typed a password into the username field: it must not reach storage.
    e = parse("Failed password for invalid user hunter2 from 203.0.113.5 port 44112 ssh2")
    assert e.username is None and "unknown user" in e.summary
    assert e.metadata["user_exists"] is False
    assert "hunter2" not in e.model_dump_json()


def test_invalid_user_probe():
    e = parse("Invalid user oracle from 203.0.113.9 port 40001")
    assert e.event_type == "auth.ssh_invalid_user" and e.username is None
    assert e.metadata["src_port"] == 40001 and "oracle" not in e.model_dump_json()


def test_legacy_invalid_user_line_without_port():
    e = parse("Invalid user oracle from 203.0.113.9")
    assert e.source_ip == "203.0.113.9" and "src_port" not in e.metadata


def test_successful_logins_drop_key_fingerprints():
    key = parse(
        "Accepted publickey for msainani from 192.168.1.20 port 51234 ssh2: "
        "ED25519 SHA256:abcDEF123"
    )
    pw = parse("Accepted password for msainani from 192.168.1.20 port 51235 ssh2")
    assert key.event_type == "auth.ssh_successful_login" and key.severity == Severity.INFO
    assert key.metadata["auth_method"] == "publickey" and "SHA256" not in key.model_dump_json()
    assert pw.metadata["auth_method"] == "password"


def test_failed_publickey_and_ipv6():
    e = parse("Failed publickey for root from 2001:DB8::1 port 5555 ssh2: RSA SHA256:zzz")
    assert e.source_ip == "2001:db8::1" and e.metadata["auth_method"] == "publickey"


def test_username_cannot_spoof_the_source_ip():
    inv = parse("Invalid user root from 9.9.9.9 port 1 from 203.0.113.5 port 55555")
    assert inv.source_ip == "203.0.113.5" and inv.metadata["src_port"] == 55555
    failed = parse(
        "Failed password for invalid user a from 9.9.9.9 port 1 ssh2 from 203.0.113.5 port 2 ssh2"
    )
    assert failed.source_ip == "203.0.113.5"


def test_invalid_address_is_malformed_not_silently_dropped():
    with pytest.raises(MalformedAuthLine):
        parse("Failed password for root from not-an-ip port 22 ssh2")


def test_event_ids_are_deterministic_per_log_entry():
    msg = "Failed password for root from 203.0.113.5 port 22 ssh2"
    assert parse(msg, eid="a").id == parse(msg, eid="a").id
    assert parse(msg, eid="a").id != parse(msg, eid="b").id
    assert parse(msg, eid="a").id != parse(msg, eid="a", source="auth_log").id


def test_pathological_input_is_fast():
    msg = "Invalid user " + "x from 1.1.1.1 port 1 " * 40 + "from zzz"
    start = time.perf_counter()
    for _ in range(50):
        with contextlib.suppress(MalformedAuthLine):  # ends in an invalid address: rejected
            parse(msg[:1000])
    assert time.perf_counter() - start < 1.0


def test_local_user_lookup_is_safe():
    assert local_user_exists("root") is True
    assert local_user_exists("definitely_not_a_user_xyz") is False
    assert local_user_exists("bad\x00name") is False
