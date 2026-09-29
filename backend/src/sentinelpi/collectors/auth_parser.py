"""Parse sshd authentication messages into normalized events. Pure functions, no I/O.

Design rules:
  * Only three outcomes are kept: failed login, invalid-user probe, successful login.
    Everything else (disconnects, PAM duplicates, banners) is ignored on purpose.
  * The attempted username is stored ONLY if it is a real local account. Failed logins
    often contain typos or passwords typed into the username field, and we must not store
    credentials. For unknown users we store no username and never echo it in the summary.
  * Usernames are attacker-controlled, so a username like "x from 9.9.9.9 port 1" must not
    change which IP we report. Patterns use a greedy user match, so the LAST
    "from <ip> port <n>" wins, and that part is always written by sshd itself.
"""

from __future__ import annotations

import ipaddress
import pwd
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import ValidationError

from sentinelpi.events import Event, EventSource, Severity

MAX_MESSAGE_CHARS = 1024  # sshd lines are short; longer input is junk (also bounds regex work)
_NS = uuid5(NAMESPACE_URL, "https://github.com/ManavSainani/SentinelPI/auth")

_FAILED = re.compile(
    r"^Failed (?P<method>[\w/-]+) for (?:invalid user )?(?P<user>.+) "
    r"from (?P<ip>\S+) port (?P<port>\d+)(?:\s.*)?$"
)
_INVALID = re.compile(
    r"^Invalid user (?P<user>.+) from (?P<ip>\S+)(?: port (?P<port>\d+))?(?:\s.*)?$"
)
_ACCEPTED = re.compile(
    r"^Accepted (?P<method>[\w/-]+) for (?P<user>.+) "
    r"from (?P<ip>\S+) port (?P<port>\d+)(?:\s.*)?$"
)


@dataclass(frozen=True)
class RawAuthEntry:
    entry_id: str  # stable per log entry (journal cursor, or "inode:offset"); drives dedupe
    timestamp: datetime  # UTC
    host: str
    message: str
    source_name: str  # "journal" or "auth_log"


class MalformedAuthLine(ValueError):
    """The line looks like a relevant auth event but its fields are invalid."""


def local_user_exists(name: str) -> bool:
    try:
        pwd.getpwnam(name)
    except (KeyError, ValueError, TypeError, OverflowError):
        return False
    return True


def _event_id(entry: RawAuthEntry) -> UUID:
    # Deterministic: re-reading the same log entry can never create a duplicate event.
    return uuid5(_NS, f"{entry.source_name}|{entry.host}|{entry.entry_id}")


def _ip(text: str) -> str:
    try:
        return str(ipaddress.ip_address(text))
    except ValueError as exc:
        raise MalformedAuthLine("invalid source address") from exc


def parse_ssh_message(
    entry: RawAuthEntry, user_exists: Callable[[str], bool] = local_user_exists
) -> Event | None:
    """Return an Event for a relevant sshd message, None if irrelevant.

    Raises MalformedAuthLine if the message is relevant but its fields don't validate.
    """
    message = entry.message.strip()
    if len(message) > MAX_MESSAGE_CHARS:
        return None

    if m := _FAILED.match(message):
        if m["method"] == "none":  # scanners probe with "none" on every connection; skip
            return None
        kind = "failed"
    elif m := _ACCEPTED.match(message):
        kind = "accepted"
    elif m := _INVALID.match(message):
        kind = "invalid"
    else:
        return None

    ip = _ip(m["ip"])
    attempted = m["user"]
    exists = bool(user_exists(attempted))
    username = attempted if exists else None
    who = username if username else "unknown user"
    port = int(m["port"]) if m.groupdict().get("port") else None
    metadata: dict[str, object] = {"user_exists": exists, "log_source": entry.source_name}
    if port is not None:
        metadata["src_port"] = port
    if kind != "invalid":
        metadata["auth_method"] = m["method"][:32]

    if kind == "failed":
        event_type, severity = "auth.ssh_failed_login", Severity.LOW
        summary = f"Failed SSH login for {who} from {ip}"
    elif kind == "invalid":
        event_type, severity = "auth.ssh_invalid_user", Severity.LOW
        summary = f"SSH login attempt with unknown user from {ip}"
        if username:
            summary = f"SSH login attempt for disallowed user {username} from {ip}"
    else:
        event_type, severity = "auth.ssh_successful_login", Severity.INFO
        summary = f"Successful SSH login for {who} from {ip}"

    try:
        return Event(
            id=_event_id(entry),
            timestamp=entry.timestamp,
            source=EventSource.AUTH_LOG,
            event_type=event_type,
            severity=severity,
            summary=summary,
            source_ip=ip,
            username=username,
            process_name="sshd",
            host=entry.host,
            metadata=metadata,
        )
    except ValidationError as exc:
        raise MalformedAuthLine("event failed validation") from exc
