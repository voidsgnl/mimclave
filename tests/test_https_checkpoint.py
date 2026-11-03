from __future__ import annotations

import io
import urllib.error
from email.message import Message

import pytest

from mirage.telemetry.checkpoints import (
    CheckpointConflictError,
    CheckpointError,
    EvidenceCheckpoint,
)
from mirage.telemetry.https_anchor import HttpsCheckpointAnchor


class FakeResponse:
    def __init__(self, status: int, body: bytes, headers: dict[str, str]) -> None:
        self.status = status
        self._body = body
        self.headers = Message()
        for name, value in headers.items():
            self.headers[name] = value

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self, size: int = -1) -> bytes:
        return self._body if size < 0 else self._body[:size]


class FakeOpener:
    def __init__(self, responses: list[object]) -> None:
        self.responses = responses
        self.requests = []

    def open(self, request, timeout: float):  # noqa: ANN001
        self.requests.append((request, timeout))
        result = self.responses.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


def http_error(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(
        "https://anchor.example/checkpoint",
        code,
        "test response",
        Message(),
        io.BytesIO(b""),
    )


def test_https_anchor_reads_checkpoint_and_requires_strong_etag(monkeypatch) -> None:
    checkpoint = EvidenceCheckpoint(1, 4, "a" * 64)
    opener = FakeOpener(
        [FakeResponse(200, b'{"generation":1,"record_count":4,"head_hash":"' +
                      b"a" * 64 + b'"}', {"ETag": '"v1"'})]
    )
    monkeypatch.setattr(
        "mirage.telemetry.https_anchor.urllib.request.build_opener",
        lambda *handlers: opener,
    )
    anchor = HttpsCheckpointAnchor(
        "https://anchor.example/checkpoint", "secret-token"
    )

    assert anchor.read() == checkpoint
    request, timeout = opener.requests[0]
    assert request.get_header("Authorization") == "Bearer secret-token"
    assert timeout == 5.0


def test_https_anchor_uses_conditional_create_and_update(monkeypatch) -> None:
    first = EvidenceCheckpoint(1, 2, "a" * 64)
    second = EvidenceCheckpoint(2, 3, "b" * 64)
    opener = FakeOpener(
        [
            http_error(404),
            FakeResponse(
                201,
                b'{"generation":1,"record_count":2,"head_hash":"' +
                b"a" * 64 + b'"}',
                {"ETag": '"v1"'},
            ),
            FakeResponse(
                200,
                b'{"generation":2,"record_count":3,"head_hash":"' +
                b"b" * 64 + b'"}',
                {"ETag": '"v2"'},
            ),
        ]
    )
    monkeypatch.setattr(
        "mirage.telemetry.https_anchor.urllib.request.build_opener",
        lambda *handlers: opener,
    )
    anchor = HttpsCheckpointAnchor(
        "https://anchor.example/checkpoint", "secret-token"
    )

    assert anchor.read() is None
    anchor.compare_and_set(expected_generation=None, checkpoint=first)
    anchor.compare_and_set(expected_generation=1, checkpoint=second)

    create_request = opener.requests[1][0]
    update_request = opener.requests[2][0]
    assert create_request.get_header("If-none-match") == "*"
    assert update_request.get_header("If-match") == '"v1"'
    assert b'"generation":2' in update_request.data


def test_https_anchor_maps_precondition_failure_to_conflict(monkeypatch) -> None:
    opener = FakeOpener([http_error(404), http_error(412)])
    monkeypatch.setattr(
        "mirage.telemetry.https_anchor.urllib.request.build_opener",
        lambda *handlers: opener,
    )
    anchor = HttpsCheckpointAnchor(
        "https://anchor.example/checkpoint", "secret-token"
    )
    assert anchor.read() is None

    with pytest.raises(CheckpointConflictError):
        anchor.compare_and_set(
            expected_generation=None,
            checkpoint=EvidenceCheckpoint(1, 1, "c" * 64),
        )


def test_https_anchor_rejects_weak_etag_and_invalid_checkpoint(monkeypatch) -> None:
    opener = FakeOpener(
        [
            FakeResponse(
                200,
                b'{"generation":1,"record_count":1,"head_hash":"' +
                b"a" * 64 + b'"}',
                {"ETag": 'W/"weak"'},
            )
        ]
    )
    monkeypatch.setattr(
        "mirage.telemetry.https_anchor.urllib.request.build_opener",
        lambda *handlers: opener,
    )
    anchor = HttpsCheckpointAnchor(
        "https://anchor.example/checkpoint", "secret-token"
    )

    with pytest.raises(CheckpointError, match="strong ETag"):
        anchor.read()


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://anchor.example/checkpoint",
        "https://user:pass@anchor.example/checkpoint",
        "https://anchor.example/checkpoint?token=bad",
        "https://anchor.example/checkpoint#fragment",
    ],
)
def test_https_anchor_rejects_unsafe_endpoint(endpoint: str) -> None:
    with pytest.raises(ValueError, match="HTTPS URL"):
        HttpsCheckpointAnchor(endpoint, "secret-token")


def test_https_anchor_rejects_redirects(monkeypatch) -> None:
    opener = FakeOpener([http_error(307)])
    monkeypatch.setattr(
        "mirage.telemetry.https_anchor.urllib.request.build_opener",
        lambda *handlers: opener,
    )
    anchor = HttpsCheckpointAnchor(
        "https://anchor.example/checkpoint", "secret-token"
    )

    with pytest.raises(CheckpointError, match="redirects are not allowed"):
        anchor.read()



def test_https_anchor_rejects_oversized_service_response(monkeypatch) -> None:
    opener = FakeOpener(
        [FakeResponse(200, b"x" * 4097, {"ETag": '"v1"'})]
    )
    monkeypatch.setattr(
        "mirage.telemetry.https_anchor.urllib.request.build_opener",
        lambda *handlers: opener,
    )
    anchor = HttpsCheckpointAnchor(
        "https://anchor.example/checkpoint", "secret-token"
    )

    with pytest.raises(CheckpointError, match="exceeds 4096 bytes"):
        anchor.read()


def test_https_anchor_rejects_duplicate_checkpoint_json_keys(monkeypatch) -> None:
    body = b'{"generation":1,"generation":2,"record_count":1,"head_hash":"' + b"a" * 64 + b'"}'
    opener = FakeOpener([FakeResponse(200, body, {"ETag": '"v1"'})])
    monkeypatch.setattr(
        "mirage.telemetry.https_anchor.urllib.request.build_opener",
        lambda *handlers: opener,
    )
    anchor = HttpsCheckpointAnchor(
        "https://anchor.example/checkpoint", "secret-token"
    )
    with pytest.raises(CheckpointError, match="invalid checkpoint"):
        anchor.read()
