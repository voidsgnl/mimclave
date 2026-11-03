"""Append-only, hash-chained JSONL storage for MIRAGE session events.

The store is Linux-first and deliberately synchronous: append returns only
after the record has been written and fsync has completed.
"""

import errno
import fcntl
import hashlib
import hmac
import json
import os
import stat
from dataclasses import dataclass
from datetime import UTC
from pathlib import Path
from typing import Any

from mirage.telemetry.events import SessionEvent

GENESIS_HASH = "0" * 64
SCHEMA_VERSION = 1
MAX_RECORD_BYTES = 64 * 1024


class EvidenceStoreError(RuntimeError):
    """Evidence could not be safely verified or durably stored."""


class EvidenceIntegrityError(EvidenceStoreError):
    """The existing evidence log is malformed, incomplete, or tampered with."""


class EvidenceEventConflictError(EvidenceStoreError):
    """An event ID was reused with a different event payload."""


@dataclass(frozen=True, slots=True)
class EvidenceReceipt:
    record_number: int
    event_id: str
    record_hash: str


@dataclass(frozen=True, slots=True)
class StoreVerification:
    record_count: int
    head_hash: str


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceIntegrityError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _canonical_json(value: dict[str, Any]) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise EvidenceStoreError("evidence record cannot be serialized") from exc


def _event_payload(event: SessionEvent) -> dict[str, Any]:
    return {
        "event_id": event.event_id,
        "session_id": event.session_id,
        "sequence": event.sequence,
        "occurred_at": event.occurred_at.astimezone(UTC).isoformat(),
        "profile_id": event.profile_id,
        "event_type": event.event_type,
        "method": event.method,
        "path": event.path,
        "status_code": event.status_code,
        "source_ip": event.source_ip,
        "source_port": event.source_port,
        "user_agent": event.user_agent,
    }


class JsonlEvidenceStore:
    """Append and verify a local hash-chained evidence log."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def append(self, event: SessionEvent) -> EvidenceReceipt:
        """Verify, append, and fsync one event under an exclusive file lock."""
        flags = os.O_CREAT | os.O_RDWR | os.O_APPEND
        flags |= getattr(os, "O_NOFOLLOW", 0)
        created = not self.path.exists()
        try:
            fd = os.open(self.path, flags, 0o600)
        except OSError as exc:
            raise EvidenceStoreError(f"cannot open evidence store: {exc}") from exc

        try:
            self._validate_file(fd)
            fcntl.flock(fd, fcntl.LOCK_EX)
            self._validate_file(fd)
            current = self._read_all(fd)
            verification, event_index = self._scan_bytes(current)
            payload = _event_payload(event)
            existing = event_index.get(event.event_id)
            if existing is not None:
                record_number, existing_payload, existing_hash = existing
                if existing_payload != payload:
                    raise EvidenceEventConflictError(
                        "event_id already exists with a different payload"
                    )
                return EvidenceReceipt(
                    record_number=record_number,
                    event_id=event.event_id,
                    record_hash=existing_hash,
                )
            unsigned = {
                "schema_version": SCHEMA_VERSION,
                "previous_hash": verification.head_hash,
                "event": payload,
            }
            record_hash = hashlib.sha256(_canonical_json(unsigned)).hexdigest()
            envelope = {**unsigned, "record_hash": record_hash}
            line = _canonical_json(envelope) + b"\n"
            if len(line) > MAX_RECORD_BYTES:
                raise EvidenceStoreError("serialized evidence record exceeds size limit")
            self._write_all(fd, line)
            os.fsync(fd)
            if created:
                self._fsync_parent()
            return EvidenceReceipt(
                record_number=verification.record_count + 1,
                event_id=event.event_id,
                record_hash=record_hash,
            )
        except EvidenceStoreError:
            raise
        except OSError as exc:
            raise EvidenceStoreError(f"evidence append failed: {exc}") from exc
        finally:
            os.close(fd)

    def verify(self) -> StoreVerification:
        """Verify the complete chain while holding a shared file lock."""
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(self.path, flags)
        except OSError as exc:
            raise EvidenceStoreError(f"cannot open evidence store: {exc}") from exc
        try:
            self._validate_file(fd)
            fcntl.flock(fd, fcntl.LOCK_SH)
            return self._verify_bytes(self._read_all(fd))
        except EvidenceStoreError:
            raise
        except OSError as exc:
            raise EvidenceStoreError(f"evidence verification failed: {exc}") from exc
        finally:
            os.close(fd)

    def _validate_file(self, fd: int) -> None:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise EvidenceStoreError("evidence store must be a regular file")
        if info.st_nlink != 1:
            raise EvidenceStoreError("evidence store must not have multiple hard links")
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise EvidenceStoreError("evidence store permissions must be 0600 or stricter")

    @staticmethod
    def _read_all(fd: int) -> bytes:
        os.lseek(fd, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        while chunk := os.read(fd, 1024 * 1024):
            chunks.append(chunk)
        return b"".join(chunks)

    @staticmethod
    def _write_all(fd: int, data: bytes) -> None:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError(errno.EIO, "short write to evidence store")
            view = view[written:]

    def _verify_bytes(self, data: bytes) -> StoreVerification:
        verification, _ = self._scan_bytes(data)
        return verification

    def _scan_bytes(
        self, data: bytes
    ) -> tuple[StoreVerification, dict[str, tuple[int, dict[str, Any], str]]]:
        event_index: dict[str, tuple[int, dict[str, Any], str]] = {}
        if not data:
            return (
                StoreVerification(record_count=0, head_hash=GENESIS_HASH),
                event_index,
            )
        if not data.endswith(b"\n"):
            raise EvidenceIntegrityError("evidence log has an incomplete trailing record")

        previous_hash = GENESIS_HASH
        count = 0
        for line_number, line in enumerate(data.splitlines(), start=1):
            if not line:
                raise EvidenceIntegrityError(
                    f"evidence log contains an empty line at record {line_number}"
                )
            if len(line) + 1 > MAX_RECORD_BYTES:
                raise EvidenceIntegrityError(
                    f"evidence record {line_number} exceeds the size limit"
                )
            try:
                envelope = json.loads(line, object_pairs_hook=_reject_duplicate_keys)
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise EvidenceIntegrityError(
                    f"evidence record {line_number} is not valid JSON"
                ) from exc
            if not isinstance(envelope, dict) or set(envelope) != {
                "schema_version", "previous_hash", "event", "record_hash"
            }:
                raise EvidenceIntegrityError(
                    f"evidence record {line_number} has an invalid envelope"
                )
            if envelope["schema_version"] != SCHEMA_VERSION:
                raise EvidenceIntegrityError(
                    f"unsupported schema version at record {line_number}"
                )
            if envelope["previous_hash"] != previous_hash:
                raise EvidenceIntegrityError(
                    f"hash-chain link mismatch at record {line_number}"
                )
            event = envelope["event"]
            if (
                not isinstance(event, dict)
                or not isinstance(event.get("event_id"), str)
                or not event["event_id"].strip()
            ):
                raise EvidenceIntegrityError(
                    f"event payload or event_id is invalid at record {line_number}"
                )
            event_id = event["event_id"]
            if event_id in event_index:
                raise EvidenceIntegrityError(
                    f"duplicate event_id at record {line_number}"
                )
            unsigned = {
                "schema_version": envelope["schema_version"],
                "previous_hash": envelope["previous_hash"],
                "event": event,
            }
            expected_hash = hashlib.sha256(_canonical_json(unsigned)).hexdigest()
            supplied_hash = envelope["record_hash"]
            if not isinstance(supplied_hash, str) or not hmac.compare_digest(
                supplied_hash, expected_hash
            ):
                raise EvidenceIntegrityError(
                    f"record hash mismatch at record {line_number}"
                )
            previous_hash = expected_hash
            count += 1
            event_index[event_id] = (count, event, expected_hash)
        return (
            StoreVerification(record_count=count, head_hash=previous_hash),
            event_index,
        )

    def _fsync_parent(self) -> None:
        parent = self.path.parent
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        directory_fd = os.open(parent, flags)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
