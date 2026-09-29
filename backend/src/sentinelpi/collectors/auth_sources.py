"""Where auth log lines come from: the systemd journal, or a classic auth.log file.

Both sources return raw entries plus a cursor so the next poll continues where this one
stopped. Neither ever runs a shell, and neither needs root: they need read access to the
logs (group `systemd-journal` or `adm`), and permission problems are reported clearly.

Trust note: journal entries carry a `_SYSTEMD_UNIT` field set by journald itself, which a
local user cannot forge (unlike the client-supplied SYSLOG_IDENTIFIER). We only accept
entries from the real ssh service. Plain files have no such guarantee: any local user can
write a fake "sshd" line to auth.log with `logger`. Prefer the journal.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import threading
import zlib
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

from sentinelpi.collectors.auth_parser import RawAuthEntry
from sentinelpi.collectors.base import CollectorState

UNIT_RE = re.compile(r"^[A-Za-z0-9:_.@-]{1,128}\.service$")
_CURSOR_RE = re.compile(r"^[A-Za-z0-9=;_.:-]{1,512}$")
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_SSH_IDENTIFIERS = {"sshd", "sshd-session"}  # OpenSSH 9.8+ logs auth from sshd-session
_PERMISSION_HINTS = ("insufficient permissions", "not seeing messages from other users")
_PERMISSION_FIX = (
    "cannot read the system journal; add the service account to the 'systemd-journal' "
    "(or 'adm') group and restart it"
)
_MONTHS = {
    m: i
    for i, m in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1
    )
}
_SYSLOG_LEGACY = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2}) +(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) (?P<ident>[\w.-]+)(?:\[\d+\])?: (?P<msg>.*)$"
)
_SYSLOG_ISO = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2}))"
    r" (?P<host>\S+) (?P<ident>[\w.-]+)(?:\[\d+\])?: (?P<msg>.*)$"
)


@dataclass
class SourceRead:
    state: CollectorState
    detail: str | None = None
    entries: list[RawAuthEntry] = field(default_factory=list)
    next_cursor: str | None = None
    ignored: int = 0
    malformed: int = 0


class AuthSource(Protocol):
    name: str

    def read(self, cursor: str | None, now: datetime) -> SourceRead: ...


# --------------------------------------------------------------------------- journal
def _field_text(value: Any) -> str | None:
    """journalctl -o json emits non-UTF8/binary MESSAGE values as arrays of byte values."""
    if isinstance(value, str):
        return value
    if isinstance(value, list) and all(isinstance(b, int) and 0 <= b < 256 for b in value):
        return bytes(value).decode("utf-8", errors="replace")
    return None


def _parse_journal_line(line: str, allowed_units: set[str]) -> tuple[str, RawAuthEntry | None]:
    """Returns (cursor, entry-or-None). Raises ValueError for malformed JSON entries."""
    obj = json.loads(line)
    if not isinstance(obj, dict):
        raise ValueError("not an object")
    cursor = obj.get("__CURSOR")
    micros = obj.get("__REALTIME_TIMESTAMP")
    if not isinstance(cursor, str) or not _CURSOR_RE.match(cursor):
        raise ValueError("missing or invalid cursor")
    if not isinstance(micros, str) or not micros.isdigit():
        raise ValueError("missing or invalid timestamp")
    if _field_text(obj.get("_SYSTEMD_UNIT")) not in allowed_units:
        return cursor, None  # not from the ssh service itself: never trusted
    message = _field_text(obj.get("MESSAGE"))
    if message is None:
        return cursor, None
    host = _field_text(obj.get("_HOSTNAME")) or "unknown"
    return cursor, RawAuthEntry(
        entry_id=cursor,
        timestamp=_EPOCH + timedelta(microseconds=int(micros)),
        host=host,
        message=message,
        source_name="journal",
    )


class JournalSource:
    name = "journal"

    def __init__(
        self,
        units: list[str],
        *,
        lookback_minutes: int = 15,
        max_entries: int = 1000,
        timeout_seconds: float = 10.0,
        popen: Callable[..., Any] = subprocess.Popen,
        which: Callable[[str], str | None] = shutil.which,
    ) -> None:
        if not units or not all(UNIT_RE.match(u) for u in units):
            raise ValueError("journal units must look like 'ssh.service'")
        self._units = units
        self._lookback = lookback_minutes
        self._max = max_entries
        self._timeout = timeout_seconds
        self._popen = popen
        self._which = which

    def _command(self, cursor: str | None, now: datetime) -> list[str]:
        cmd = [
            "journalctl",
            "--no-pager",
            "-o",
            "json",
            "--output-fields=MESSAGE,_SYSTEMD_UNIT,_HOSTNAME",
        ]
        cmd += [f"--unit={u}" for u in self._units]
        if cursor and _CURSOR_RE.match(cursor):
            cmd.append(f"--after-cursor={cursor}")
        else:
            since = (now - timedelta(minutes=self._lookback)).astimezone(UTC)
            cmd.append(f"--since={since:%Y-%m-%d %H:%M:%S} UTC")
        return cmd

    def read(self, cursor: str | None, now: datetime) -> SourceRead:
        return self._read(cursor, now, allow_retry=True)

    def _read(self, cursor: str | None, now: datetime, *, allow_retry: bool) -> SourceRead:
        if self._which("journalctl") is None:
            return SourceRead(CollectorState.UNAVAILABLE, "journalctl not found (no systemd)")
        env = {"LC_ALL": "C", "PATH": os.environ.get("PATH", "/usr/bin:/bin")}
        try:
            proc = self._popen(
                self._command(cursor, now),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=env,
            )
        except FileNotFoundError:
            return SourceRead(CollectorState.UNAVAILABLE, "journalctl not found (no systemd)")
        except OSError as exc:
            return SourceRead(
                CollectorState.ERROR, f"could not start journalctl: {type(exc).__name__}"
            )

        timer = threading.Timer(self._timeout, proc.kill)
        timer.daemon = True
        timer.start()
        lines: list[str] = []
        truncated = False
        try:
            for line in proc.stdout:
                lines.append(line)
                if len(lines) >= self._max:
                    truncated = True  # more remains; the next poll continues from the cursor
                    proc.kill()
                    break
        finally:
            timer.cancel()
        stderr = proc.stderr.read() if proc.stderr else ""
        proc.wait()

        if any(hint in stderr.lower() for hint in _PERMISSION_HINTS):
            return SourceRead(CollectorState.UNAVAILABLE, _PERMISSION_FIX)
        if proc.returncode not in (0, None) and not truncated:
            if cursor and allow_retry and "cursor" in stderr.lower():
                # Cursor no longer exists (journal vacuumed/rotated): fall back to lookback.
                retried = self._read(None, now, allow_retry=False)
                if retried.state == CollectorState.OK:
                    retried.state = CollectorState.DEGRADED
                    retried.detail = "saved journal cursor was invalid; restarted from lookback"
                return retried
            return SourceRead(
                CollectorState.ERROR, f"journalctl exited with status {proc.returncode}"
            )

        allowed = set(self._units)
        out = SourceRead(CollectorState.OK, next_cursor=cursor)
        for raw in lines:
            text = raw.strip()
            if not text or text.startswith("-- "):
                continue
            try:
                entry_cursor, entry = _parse_journal_line(text, allowed)
            except ValueError:  # includes json.JSONDecodeError
                out.malformed += 1
                continue
            out.next_cursor = entry_cursor  # advance past everything we have seen
            if entry is None:
                out.ignored += 1
            else:
                out.entries.append(entry)
        return out


# --------------------------------------------------------------------------- auth.log
def parse_syslog_line(line: str, now: datetime) -> tuple[datetime, str, str, str] | None:
    """Parse one syslog line into (utc_time, host, identifier, message), or None."""
    m = _SYSLOG_ISO.match(line)
    if m:
        text = m["ts"].replace("Z", "+00:00")
        if re.search(r"[+-]\d{4}$", text):  # +0200 -> +02:00 for fromisoformat
            text = f"{text[:-2]}:{text[-2:]}"
        try:
            ts = datetime.fromisoformat(text).astimezone(UTC)
        except ValueError:
            return None
        return ts, m["host"], m["ident"], m["msg"]
    m = _SYSLOG_LEGACY.match(line)
    if not m or m["mon"] not in _MONTHS:
        return None
    h, mi, s = (int(x) for x in m["time"].split(":"))
    # Legacy syslog has no year or zone: assume the current year in the host's local time,
    # and step back a year for December lines read in January.
    for year in (now.year, now.year - 1):
        try:
            local = datetime(year, _MONTHS[m["mon"]], int(m["day"]), h, mi, s)
        except ValueError:
            continue
        ts = local.astimezone(UTC)  # naive datetime => interpreted in system local time
        if ts <= now + timedelta(days=1):
            return ts, m["host"], m["ident"], m["msg"]
    return None


class AuthLogFileSource:
    name = "auth_log"
    _INITIAL_TAIL_BYTES = 256 * 1024
    _MAX_READ_BYTES = 512 * 1024

    def __init__(
        self, paths: list[str], *, lookback_minutes: int = 15, max_entries: int = 1000
    ) -> None:
        self._paths = paths
        self._lookback = lookback_minutes
        self._max = max_entries

    def read(self, cursor: str | None, now: datetime) -> SourceRead:
        path = next((Path(p) for p in self._paths if Path(p).exists()), None)
        if path is None:
            return SourceRead(
                CollectorState.UNAVAILABLE, f"no auth log file found ({', '.join(self._paths)})"
            )
        try:
            st = path.stat()
            with path.open("rb") as fh:
                return self._read_open(fh, st, cursor, now)
        except PermissionError:
            return SourceRead(
                CollectorState.UNAVAILABLE,
                f"permission denied reading {path}; add the service account to the 'adm' group",
            )
        except OSError as exc:
            return SourceRead(CollectorState.ERROR, f"could not read {path}: {type(exc).__name__}")

    @staticmethod
    def _head(fh: Any, upto: int) -> str:
        """Checksum of the first bytes already consumed. If the file was truncated and
        rewritten (e.g. logrotate copytruncate) those bytes change even when the size
        doesn't, so we notice and re-read from the top."""
        fh.seek(0)
        return f"{zlib.crc32(fh.read(min(64, upto))):08x}"

    def _read_open(
        self, fh: Any, st: os.stat_result, cursor: str | None, now: datetime
    ) -> SourceRead:
        inode, size = st.st_ino, st.st_size
        start, resumed = 0, False
        if cursor:
            try:
                c_inode_s, c_off_s, c_head = cursor.split(":", 2)
                c_inode, c_off = int(c_inode_s), int(c_off_s)
            except ValueError:
                c_inode, c_off, c_head = -1, 0, ""
            if c_inode == inode and 0 <= c_off <= size and self._head(fh, c_off) == c_head:
                start, resumed = c_off, True  # otherwise rotated/truncated/rewritten: from top
        else:
            start = max(0, size - self._INITIAL_TAIL_BYTES)
        fh.seek(start)
        data = fh.read(self._MAX_READ_BYTES)
        end = data.rfind(b"\n") + 1  # only complete lines; a partial tail waits for next poll

        def cursor_at(offset: int) -> str:
            return f"{inode}:{offset}:{self._head(fh, offset)}"

        out = SourceRead(CollectorState.OK, next_cursor=cursor_at(start + end))
        if end == 0:
            if len(data) >= self._MAX_READ_BYTES:  # one enormous line: skip it
                out.next_cursor = cursor_at(start + len(data))
            else:
                out.next_cursor = cursor if resumed else cursor_at(start)
            return out

        oldest = now - timedelta(minutes=self._lookback)
        pos = start
        for i, raw in enumerate(data[:end].split(b"\n")[:-1]):
            line_start, pos = pos, pos + len(raw) + 1
            if i == 0 and start > 0 and not resumed:
                continue  # initial tail may begin mid-line
            if len(out.entries) >= self._max:
                out.next_cursor = cursor_at(line_start)  # continue here next poll
                break
            parsed = parse_syslog_line(raw.decode("utf-8", errors="replace"), now)
            if parsed is None:
                out.malformed += 1
                continue
            ts, host, ident, msg = parsed
            if ident not in _SSH_IDENTIFIERS or (not cursor and ts < oldest):
                out.ignored += 1
                continue
            out.entries.append(RawAuthEntry(f"{inode}:{line_start}", ts, host, msg, self.name))
        return out
