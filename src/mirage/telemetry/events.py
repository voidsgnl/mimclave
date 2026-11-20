"""Structured HTTP session events with conservative collection defaults.

Only explicitly selected metadata is recorded. Request bodies, cookies,
authorization headers, query strings, and form values are never represented
by this event schema.
"""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import ip_address
from threading import Lock
from urllib.parse import urlsplit
from uuid import uuid4

MAX_PATH_LENGTH = 2048
MAX_USER_AGENT_LENGTH = 256


def _validate_utc(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None or value.utcoffset().total_seconds() != 0:
        raise ValueError("occurred_at must be timezone-aware UTC")


def _clean_user_agent(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = "".join(
        char if char.isprintable() and char not in "\r\n\t" else " "
        for char in value
    )
    return cleaned[:MAX_USER_AGENT_LENGTH]


@dataclass(frozen=True, slots=True)
class SessionEvent:
    """One immutable observation from a MIRAGE-controlled decoy session."""

    event_id: str
    session_id: str
    sequence: int
    occurred_at: datetime
    profile_id: str
    event_type: str
    method: str
    path: str
    status_code: int
    source_ip: str | None = None
    source_port: int | None = None
    user_agent: str | None = None

    def __post_init__(self) -> None:
        for name in ("event_id", "session_id", "profile_id", "event_type", "method", "path"):
            if not getattr(self, name).strip():
                raise ValueError(f"{name} must not be empty")
        if self.sequence < 1:
            raise ValueError("sequence must be positive")
        _validate_utc(self.occurred_at)
        if not 100 <= self.status_code <= 599:
            raise ValueError("status_code must be between 100 and 599")
        if self.source_ip is not None:
            try:
                normalized = str(ip_address(self.source_ip))
            except ValueError as exc:
                raise ValueError("source_ip must be a valid IP address") from exc
            object.__setattr__(self, "source_ip", normalized)
        if self.source_port is not None and not 1 <= self.source_port <= 65535:
            raise ValueError("source_port must be between 1 and 65535")
        if (
            not self.path.startswith("/")
            or self.path.startswith("//")
            or "?" in self.path
            or "#" in self.path
            or len(self.path) > MAX_PATH_LENGTH
            or any(ord(c) < 32 for c in self.path)
        ):
            raise ValueError("path must be a bounded origin-form path without query or fragment")
        if self.user_agent is not None and len(self.user_agent) > MAX_USER_AGENT_LENGTH:
            raise ValueError("user_agent exceeds the maximum length")


class SessionEventFactory:
    """Assign correlation IDs and strictly increasing sequence numbers per session."""

    def __init__(
        self,
        profile_id: str,
        *,
        session_id: str | None = None,
        capture_user_agent: bool = False,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not profile_id.strip():
            raise ValueError("profile_id must not be empty")
        self.profile_id = profile_id
        self.session_id = session_id or str(uuid4())
        if not self.session_id.strip():
            raise ValueError("session_id must not be empty")
        self.capture_user_agent = capture_user_agent
        self._clock = clock or (lambda: datetime.now(UTC))
        self._sequence = 0
        self._lock = Lock()

    def record_http_request(
        self,
        *,
        method: str,
        target: str,
        status_code: int,
        source_ip: str | None = None,
        source_port: int | None = None,
        user_agent: str | None = None,
    ) -> SessionEvent:
        """Create an event without retaining query strings or request secrets."""
        if not method.strip():
            raise ValueError("method must not be empty")
        if not target.startswith("/") or target.startswith("//"):
            raise ValueError("target must be an origin-form path")
        path = urlsplit(target).path
        if not path or len(path) > MAX_PATH_LENGTH or any(ord(c) < 32 for c in path):
            raise ValueError("request path is invalid or too long")

        if not 100 <= status_code <= 599:
            raise ValueError("status_code must be between 100 and 599")
        if source_port is not None and not 1 <= source_port <= 65535:
            raise ValueError("source_port must be between 1 and 65535")
        if source_ip is not None:
            try:
                source_ip = str(ip_address(source_ip))
            except ValueError as exc:
                raise ValueError("source_ip must be a valid IP address") from exc
        timestamp = self._clock()
        _validate_utc(timestamp)
        captured_agent = (
            _clean_user_agent(user_agent)
            if self.capture_user_agent
            else None
        )

        with self._lock:
            self._sequence += 1
            sequence = self._sequence

        return SessionEvent(
            event_id=str(uuid4()),
            session_id=self.session_id,
            sequence=sequence,
            occurred_at=timestamp,
            profile_id=self.profile_id,
            event_type="http.request",
            method=method.upper(),
            path=path,
            status_code=status_code,
            source_ip=source_ip,
            source_port=source_port,
            user_agent=captured_agent,
        )

    def record_terminal_command(
        self,
        *,
        command_name: str,
        source_ip: str | None = None,
        source_port: int | None = None,
    ) -> SessionEvent:
        """Record command metadata only; never retain command arguments or input."""
        import re

        if not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", command_name):
            raise ValueError("command_name must be a bounded command identifier")
        if source_ip is not None:
            try:
                source_ip = str(ip_address(source_ip))
            except ValueError as exc:
                raise ValueError("source_ip must be a valid IP address") from exc
        if source_port is not None and not 1 <= source_port <= 65535:
            raise ValueError("source_port must be between 1 and 65535")

        timestamp = self._clock()
        _validate_utc(timestamp)
        with self._lock:
            self._sequence += 1
            sequence = self._sequence

        return SessionEvent(
            event_id=str(uuid4()),
            session_id=self.session_id,
            sequence=sequence,
            occurred_at=timestamp,
            profile_id=self.profile_id,
            event_type="ssh.command",
            method="SSH",
            path=f"/terminal/{command_name}",
            status_code=200,
            source_ip=source_ip,
            source_port=source_port,
        )
