import json
from uuid import uuid4

import pytest

from mirage.sandbox.ipc import (
    MAX_WORKER_MESSAGE_BYTES,
    WorkerEvent,
    WorkerEventSequenceGuard,
    WorkerMessageError,
    decode_worker_event,
    encode_worker_event,
)


def event(*, session_id: str | None = None, sequence: int = 1, **kwargs) -> WorkerEvent:
    values = {
        "event_id": str(uuid4()),
        "session_id": session_id or str(uuid4()),
        "sequence": sequence,
        "event_type": "http.request",
        "timestamp": "2026-11-20T18:00:00+00:00",
        "profile_id": "web-decoy",
        "protocol": "http",
        "source_ip": "192.0.2.10",
        "source_port": 49152,
        "method": "GET",
        "request_path": "/login",
        "status_code": 200,
    }
    values.update(kwargs)
    return WorkerEvent(**values)


def test_worker_event_round_trip_is_deterministic() -> None:
    item = event()
    encoded = encode_worker_event(item)
    assert encoded.endswith(b"\n")
    assert decode_worker_event(encoded) == item
    assert encode_worker_event(item) == encoded


def test_worker_event_does_not_accept_raw_command_or_secret_fields() -> None:
    payload = json.loads(encode_worker_event(event()))
    payload["command"] = "cat /etc/shadow"
    with pytest.raises(WorkerMessageError, match="unsupported fields"):
        decode_worker_event(json.dumps(payload).encode() + b"\n")


@pytest.mark.parametrize(
    "frame",
    [
        b"",
        b"not-json\n",
        b"{}",
        b"{}\n{}\n",
        b" " * (MAX_WORKER_MESSAGE_BYTES + 1),
        b'{"x":1,"x":2}\n',
        b'{"x":NaN}\n',
    ],
)
def test_decoder_rejects_invalid_or_ambiguous_frames(frame: bytes) -> None:
    with pytest.raises(WorkerMessageError):
        decode_worker_event(frame)


def test_decoder_rejects_unknown_and_missing_fields() -> None:
    payload = json.loads(encode_worker_event(event()))
    del payload["profile_id"]
    payload["password"] = "never-accept"
    with pytest.raises(WorkerMessageError, match="missing fields"):
        decode_worker_event(json.dumps(payload).encode() + b"\n")


@pytest.mark.parametrize(
    "kwargs, message",
    [
        ({"timestamp": "2026-11-20T18:00:00"}, "timezone offset"),
        ({"source_ip": "not-an-ip"}, "valid IP"),
        ({"source_port": 0}, "source_port"),
        ({"method": "get"}, "uppercase token"),
        ({"request_path": "/login?token=secret"}, "sanitized"),
        ({"request_path": "login"}, "sanitized"),
        ({"status_code": 99}, "status_code"),
        ({"command_name": "cat /etc/passwd"}, "normalized command"),
    ],
)
def test_worker_event_rejects_unsafe_metadata(kwargs, message: str) -> None:
    with pytest.raises(WorkerMessageError, match=message):
        event(**kwargs)


def test_event_rejects_oversized_request_path() -> None:
    with pytest.raises(WorkerMessageError, match="sanitized"):
        event(request_path="/" + ("a" * 3000))


def test_sequence_guard_requires_monotonic_per_session_order() -> None:
    guard = WorkerEventSequenceGuard(max_sessions=2)
    session = str(uuid4())
    guard.accept(event(session_id=session, sequence=1))
    guard.accept(event(session_id=session, sequence=2))
    with pytest.raises(WorkerMessageError, match="strictly increasing"):
        guard.accept(event(session_id=session, sequence=2))
    with pytest.raises(WorkerMessageError, match="strictly increasing"):
        guard.accept(event(session_id=session, sequence=4))


def test_sequence_guard_bounds_sessions_and_releases_closed_state() -> None:
    guard = WorkerEventSequenceGuard(max_sessions=1)
    first = str(uuid4())
    second = str(uuid4())
    guard.accept(event(session_id=first))
    with pytest.raises(WorkerMessageError, match="maximum active"):
        guard.accept(event(session_id=second))
    guard.close_session(first)
    guard.accept(event(session_id=second))


def test_sequence_guard_can_validate_without_consuming_sequence() -> None:
    guard = WorkerEventSequenceGuard()
    session = str(uuid4())
    first = event(session_id=session, sequence=1)
    guard.validate(first)
    guard.validate(first)
    guard.accept(first)
    guard.validate(event(session_id=session, sequence=2))
