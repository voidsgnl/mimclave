"""HTTPS client for an independently hosted MIRAGE checkpoint anchor.

The remote service must implement the conditional HTTP contract documented in
docs/evidence-storage.md. TLS certificate verification is always enabled and
redirects are refused so bearer credentials cannot be forwarded elsewhere.
"""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from dataclasses import asdict
from urllib.parse import urlsplit

from mirage.telemetry.checkpoints import (
    CheckpointConflictError,
    CheckpointError,
    EvidenceCheckpoint,
)


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


class HttpsCheckpointAnchor:
    """Publish checkpoints to a remote HTTPS service using ETag compare-and-set.

    Construct with the exact checkpoint resource URL and a bearer token. The
    service must retain durable state independently of the evidence host.
    """

    def __init__(
        self,
        endpoint: str,
        bearer_token: str,
        *,
        timeout: float = 5.0,
    ) -> None:
        parsed = urlsplit(endpoint)
        try:
            parsed.port
        except ValueError as exc:
            raise ValueError("checkpoint endpoint has an invalid port") from exc
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError(
                "checkpoint endpoint must be an HTTPS URL without credentials, query, or fragment"
            )
        if not bearer_token or bearer_token.strip() != bearer_token:
            raise ValueError("bearer token must be non-empty and have no surrounding whitespace")
        if timeout <= 0:
            raise ValueError("timeout must be positive")

        self._endpoint = endpoint
        self._token = bearer_token
        self._timeout = timeout
        self._etag: str | None = None
        self._observed_generation: int | None = None
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ssl.create_default_context()),
            _NoRedirectHandler(),
        )

    def read(self) -> EvidenceCheckpoint | None:
        request = urllib.request.Request(
            self._endpoint,
            headers=self._headers(),
            method="GET",
        )
        try:
            with self._opener.open(request, timeout=self._timeout) as response:
                if response.status != 200:
                    raise CheckpointError(
                        f"checkpoint service returned unexpected HTTP {response.status}"
                    )
                checkpoint = self._decode_checkpoint(self._read_bounded(response))
                etag = response.headers.get("ETag")
                if not self._is_strong_etag(etag):
                    raise CheckpointError(
                        "checkpoint service must return a strong ETag"
                    )
                self._etag = etag
                self._observed_generation = checkpoint.generation
                return checkpoint
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                self._etag = None
                self._observed_generation = None
                return None
            if 300 <= exc.code < 400:
                raise CheckpointError("checkpoint service redirects are not allowed") from exc
            raise CheckpointError(
                f"checkpoint service read failed with HTTP {exc.code}"
            ) from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise CheckpointError("checkpoint service could not be reached") from exc

    def compare_and_set(
        self,
        *,
        expected_generation: int | None,
        checkpoint: EvidenceCheckpoint,
    ) -> None:
        if expected_generation != self._observed_generation:
            raise CheckpointConflictError(
                "expected generation does not match the most recently read checkpoint"
            )
        expected_next = 1 if expected_generation is None else expected_generation + 1
        if checkpoint.generation != expected_next:
            raise CheckpointConflictError("checkpoint generation is not monotonic")

        headers = self._headers()
        if self._etag is None:
            headers["If-None-Match"] = "*"
        else:
            headers["If-Match"] = self._etag

        body = json.dumps(
            asdict(checkpoint), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        request = urllib.request.Request(
            self._endpoint,
            data=body,
            headers=headers,
            method="PUT",
        )
        try:
            with self._opener.open(request, timeout=self._timeout) as response:
                if response.status not in (200, 201):
                    raise CheckpointError(
                        f"checkpoint service returned unexpected HTTP {response.status}"
                    )
                stored = self._decode_checkpoint(self._read_bounded(response))
                etag = response.headers.get("ETag")
                if stored != checkpoint or not self._is_strong_etag(etag):
                    raise CheckpointError(
                        "checkpoint service response does not confirm the published checkpoint"
                    )
                self._etag = etag
                self._observed_generation = checkpoint.generation
        except urllib.error.HTTPError as exc:
            if exc.code in (409, 412):
                raise CheckpointConflictError(
                    "external checkpoint changed before conditional publication"
                ) from exc
            if 300 <= exc.code < 400:
                raise CheckpointError("checkpoint service redirects are not allowed") from exc
            raise CheckpointError(
                f"checkpoint service write failed with HTTP {exc.code}"
            ) from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise CheckpointError("checkpoint service could not be reached") from exc

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    @staticmethod
    def _read_bounded(response: object) -> bytes:
        data = response.read(4097)  # type: ignore[attr-defined]
        if len(data) > 4096:
            raise CheckpointError("checkpoint service response exceeds 4096 bytes")
        return data

    @staticmethod
    def _decode_checkpoint(data: bytes) -> EvidenceCheckpoint:
        try:
            payload = json.loads(data)
            if not isinstance(payload, dict) or set(payload) != {
                "generation", "record_count", "head_hash"
            }:
                raise ValueError("invalid checkpoint fields")
            if (
                isinstance(payload["generation"], bool)
                or not isinstance(payload["generation"], int)
                or isinstance(payload["record_count"], bool)
                or not isinstance(payload["record_count"], int)
                or not isinstance(payload["head_hash"], str)
            ):
                raise ValueError("invalid checkpoint field types")
            return EvidenceCheckpoint(**payload)
        except (json.JSONDecodeError, UnicodeDecodeError, TypeError, ValueError) as exc:
            raise CheckpointError("checkpoint service returned an invalid checkpoint") from exc

    @staticmethod
    def _is_strong_etag(etag: str | None) -> bool:
        return (
            etag is not None
            and len(etag) >= 2
            and etag.startswith('"')
            and etag.endswith('"')
            and not etag.startswith('W/')
            and "\r" not in etag
            and "\n" not in etag
        )
