"""Bounded worker-to-supervisor event message contract.

This module provides serialization and validation only. It does not open IPC
sockets or grant workers access to evidence storage.
"""

from dataclasses import asdict, dataclass
from datetime import datetime
from ipaddress import ip_address
import json
import re
from uuid import UUID

MAX_WORKER_MESSAGE_BYTES = 16 * 1024
MAX_ACTIVE_WORKER_SESSIONS = 1024

_REQUIRED_FIELDS = frozenset(
    {
        "event_id",
        "session_id",
        "sequence",
        "event_type",
        "timestamp",
        "profile_id",
        "protocol",
    }
)
_ALLOWED_FIELDS = _REQUIRED_FIELDS | frozenset(
    {
        "source_ip",
        "source_port",
        "method",
        "request_path",
        "status_code",
        "command_name",
    }
)
_IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_EVENT_TYPE = re.compile(r"[a-z][a-z0-9_.-]{0,63}")
_COMMAND_NAME = re.compile(r"[a-z][a-z0-9_-]{0,31}")
_METHOD = re.compile(r"[A-Z][A-Z0-9_-]{0,15}")
_PROTOCOLS = frozenset({"http", "https", "ssh"})


class WorkerMessageError(ValueError):
    """Raised when a worker event violates the IPC contract."""


@dataclass(frozen=True, slots=True)
class WorkerEvent:
    """A deliberately narrow event; raw commands and secret-bearing data are absent."""

    event_id: str
    session_id: str
    sequence: int
    event_type: str
    timestamp: str
    profile_id: str
    protocol: str
    source_ip: str | None = None
    source_port: int | None = None
    method: str | None = None
    request_path: str | None = None
    status_code: int | None = None
    command_name: str | None = None

    def __post_init__(self) -> None:
        for field_name in ("event_id", "session_id"):
            value = getattr(self, field_name)
            if not isinstance(value, str):
                raise WorkerMessageError(f"{field_name} must be a UUID string")
            try:
                if str(UUID(value)) != value.lower():
                    raise ValueError
            except ValueError as exc:
                raise WorkerMessageError(f"{field_name} must be a canonical UUID") from exc

        if isinstance(self.sequence, bool) or not isinstance(self.sequence, int):
            raise WorkerMessageError("sequence must be an integer")
        if self.sequence < 1:
            raise WorkerMessageError("sequence must be positive")

        if not isinstance(self.event_type, str) or not _EVENT_TYPE.fullmatch(self.event_type):
            raise WorkerMessageError("event_type has an invalid format")
        if not isinstance(self.profile_id, str) or not _IDENTIFIER.fullmatch(self.profile_id):
            raise WorkerMessageError("profile_id has an invalid format")
        if not isinstance(self.protocol, str) or self.protocol not in _PROTOCOLS:
            raise WorkerMessageError("protocol must be http, https, or ssh")

        if not isinstance(self.timestamp, str):
            raise WorkerMessageError("timestamp must be an ISO-8601 string")
        try:
            parsed = datetime.fromisoformat(self.timestamp.replace("Z", "+00:00"))
        except ValueError as exc:
            raise WorkerMessageError("timestamp must be a valid ISO-8601 value") from exc
        offset = parsed.utcoffset()
        if offset is None or offset.total_seconds() != 0:
            raise WorkerMessageError("timestamp must use a UTC timezone offset")

        if self.source_ip is not None:
            if not isinstance(self.source_ip, str):
                raise WorkerMessageError("source_ip must be an IP address string")
            try:
                ip_address(self.source_ip)
            except ValueError as exc:
                raise WorkerMessageError("source_ip must be a valid IP address") from exc
        if self.source_port is not None:
            if (
                isinstance(self.source_port, bool)
                or not isinstance(self.source_port, int)
                or not 1 <= self.source_port <= 65535
            ):
                raise WorkerMessageError("source_port must be between 1 and 65535")
        if self.source_port is not None and self.source_ip is None:
            raise WorkerMessageError("source_port requires source_ip")

        if self.method is not None:
            if not isinstance(self.method, str) or not _METHOD.fullmatch(self.method):
                raise WorkerMessageError("method must be a bounded uppercase token")
        if self.request_path is not None:
            if (
                not isinstance(self.request_path, str)
                or not self.request_path.startswith("/")
                or len(self.request_path) > 2048
                or "?" in self.request_path
                or "#" in self.request_path
                or any(ord(char) < 32 or ord(char) == 127 for char in self.request_path)
            ):
                raise WorkerMessageError("request_path must be a sanitized absolute path")
        if self.status_code is not None:
            if (
                isinstance(self.status_code, bool)
                or not isinstance(self.status_code, int)
                or not 100 <= self.status_code <= 599
            ):
                raise WorkerMessageError("status_code must be between 100 and 599")
        if self.command_name is not None:
            if not isinstance(self.command_name, str) or not _COMMAND_NAME.fullmatch(
                self.command_name
            ):
                raise WorkerMessageError("command_name must be a normalized command identifier")


def encode_worker_event(event: WorkerEvent) -> bytes:
    """Encode one event as a bounded newline-delimited JSON frame."""

    payload = json.dumps(
        asdict(event),
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8") + b"\n"
    if len(payload) > MAX_WORKER_MESSAGE_BYTES:
        raise WorkerMessageError("worker event exceeds the maximum message size")
    return payload


def _reject_json_constant(value: str) -> None:
    raise WorkerMessageError(f"invalid JSON constant: {value}")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise WorkerMessageError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def decode_worker_event(frame: bytes) -> WorkerEvent:
    """Decode exactly one bounded JSON frame and reject unknown or secret fields."""

    if not isinstance(frame, bytes):
        raise WorkerMessageError("worker frame must be bytes")
    if not frame or len(frame) > MAX_WORKER_MESSAGE_BYTES:
        raise WorkerMessageError("worker frame is empty or exceeds the maximum size")
    if not frame.endswith(b"\n") or b"\n" in frame[:-1]:
        raise WorkerMessageError("worker frame must contain exactly one newline-terminated message")

    try:
        payload = frame[:-1].decode("utf-8", errors="strict")
        decoded = json.loads(
            payload,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WorkerMessageError("worker frame is not valid UTF-8 JSON") from exc

    if not isinstance(decoded, dict):
        raise WorkerMessageError("worker event must be a JSON object")

    keys = set(decoded)
    missing = _REQUIRED_FIELDS - keys
    unknown = keys - _ALLOWED_FIELDS
    if missing:
        raise WorkerMessageError(f"worker event is missing fields: {', '.join(sorted(missing))}")
    if unknown:
        fields = ", ".join(sorted(unknown))
        raise WorkerMessageError(f"worker event contains unsupported fields: {fields}")

    try:
        return WorkerEvent(**decoded)
    except TypeError as exc:
        raise WorkerMessageError("worker event fields do not match the IPC contract") from exc


class WorkerEventSequenceGuard:
    """Enforce per-session monotonic sequence numbers in a serialized broker."""

    def __init__(self, *, max_sessions: int = MAX_ACTIVE_WORKER_SESSIONS) -> None:
        if isinstance(max_sessions, bool) or not isinstance(max_sessions, int) or max_sessions < 1:
            raise ValueError("max_sessions must be a positive integer")
        self._max_sessions = max_sessions
        self._last_sequence: dict[str, int] = {}

    def validate(self, event: WorkerEvent) -> None:
        """Check the next event without changing sequence state."""

        previous = self._last_sequence.get(event.session_id)
        if previous is None:
            if len(self._last_sequence) >= self._max_sessions:
                raise WorkerMessageError("maximum active worker sessions reached")
            if event.sequence != 1:
                raise WorkerMessageError("first event in a session must have sequence 1")
        elif event.sequence != previous + 1:
            raise WorkerMessageError("worker event sequence is not strictly increasing")

    def accept(self, event: WorkerEvent) -> None:
        """Commit the next sequence after its evidence record is durable."""

        self.validate(event)
        self._last_sequence[event.session_id] = event.sequence

    def close_session(self, session_id: str) -> None:
        """Release sequence state after the broker has closed a session."""

        self._last_sequence.pop(session_id, None)
