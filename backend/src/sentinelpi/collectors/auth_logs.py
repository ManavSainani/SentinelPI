"""Authentication log collector: pick a source, parse new entries, report status."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

from pydantic import BaseModel

from sentinelpi.collectors.auth_parser import (
    MalformedAuthLine,
    local_user_exists,
    parse_ssh_message,
)
from sentinelpi.collectors.auth_sources import AuthLogFileSource, AuthSource, JournalSource
from sentinelpi.collectors.base import CollectionResult, CollectorState, make_status
from sentinelpi.config import AuthSettings
from sentinelpi.events import Event
from sentinelpi.timeutil import utc_now

NAME = "auth_logs"


class AuthBatch(BaseModel):
    source: str
    events: list[Event]
    entries_read: int
    ignored: int
    malformed: int


class AuthPoll(BaseModel):
    result: CollectionResult[AuthBatch]
    cursors: dict[str, str]  # updated per-source cursors; persist only on success


class AuthLogCollector:
    def __init__(
        self,
        sources: list[AuthSource],
        user_exists: Callable[[str], bool] = local_user_exists,
    ) -> None:
        self._sources = sources
        self._user_exists = user_exists

    @property
    def source_names(self) -> list[str]:
        return [s.name for s in self._sources]

    def poll(self, cursors: dict[str, str], now: datetime | None = None) -> AuthPoll:
        now = now or utc_now()
        skipped: list[str] = []
        for source in self._sources:
            read = source.read(cursors.get(source.name), now)
            if read.state in (CollectorState.UNAVAILABLE, CollectorState.ERROR):
                skipped.append(f"{source.name}: {read.detail}")
                continue
            events: list[Event] = []
            ignored, malformed = read.ignored, read.malformed  # already dropped by the source
            for entry in read.entries:
                try:
                    event = parse_ssh_message(entry, self._user_exists)
                except MalformedAuthLine:
                    malformed += 1
                    continue
                if event is None:
                    ignored += 1
                else:
                    events.append(event)
            batch = AuthBatch(
                source=source.name,
                events=events,
                entries_read=len(read.entries) + read.ignored + read.malformed,
                ignored=ignored,
                malformed=malformed,
            )
            notes = [f"source={source.name}"]
            if read.detail:
                notes.append(read.detail)
            if skipped:
                notes.append("skipped: " + "; ".join(skipped))
            if malformed:
                notes.append(f"{malformed} malformed line(s) skipped")
            new_cursors = dict(cursors)
            if read.next_cursor:
                new_cursors[source.name] = read.next_cursor
            state = (
                CollectorState.DEGRADED
                if (read.state == CollectorState.DEGRADED or skipped)
                else CollectorState.OK
            )
            return AuthPoll(
                result=CollectionResult[AuthBatch](
                    status=make_status(NAME, state, "; ".join(notes)), data=batch
                ),
                cursors=new_cursors,
            )

        all_unavailable = "; ".join(skipped) or "no auth log sources configured"
        return AuthPoll(
            result=CollectionResult[AuthBatch](
                status=make_status(NAME, CollectorState.UNAVAILABLE, all_unavailable)
            ),
            cursors=dict(cursors),
        )


def build_auth_collector(settings: AuthSettings) -> AuthLogCollector:
    return AuthLogCollector(
        [
            JournalSource(
                settings.journal_units,
                lookback_minutes=settings.initial_lookback_minutes,
                max_entries=settings.max_entries_per_poll,
            ),
            AuthLogFileSource(
                settings.auth_log_paths,
                lookback_minutes=settings.initial_lookback_minutes,
                max_entries=settings.max_entries_per_poll,
            ),
        ]
    )
