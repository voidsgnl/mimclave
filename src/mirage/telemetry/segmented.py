"""Crash-safe segmented evidence storage.

The legacy JsonlEvidenceStore remains unchanged. This store uses a hash-chained
manifest to join immutable segments into one continuous evidence chain.
"""
from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import re
import stat
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mirage.telemetry.checkpoints import CheckpointAnchor, CheckpointError
from mirage.telemetry.events import SessionEvent
from mirage.telemetry.store import (
    GENESIS_HASH,
    MAX_RECORD_BYTES,
    SCHEMA_VERSION,
    EvidenceEventConflictError,
    EvidenceIntegrityError,
    EvidenceReceipt,
    EvidenceStoreError,
    StoreVerification,
    _canonical_json,
    _event_payload,
    _reject_duplicate_keys,
)

_SEGMENT_RE = re.compile(r"^segment-(\d{8})\.jsonl$")
_MANIFEST = "manifest.jsonl"


class CheckpointUnavailableError(CheckpointError):
    """The independent checkpoint service could not be reached."""


@dataclass(frozen=True, slots=True)
class _Segment:
    segment_id: int
    file_name: str
    first_record_number: int
    start_previous_hash: str
    opened: bool = True
    record_count: int = 0
    last_record_number: int = 0
    last_hash: str = GENESIS_HASH
    file_size: int = 0
    file_sha256: str = ""
    checkpoint_generation: int = 0
    retired: bool = False
    export_sha256: str = ""


class SegmentedEvidenceStore:
    """Segmented append-only evidence store with explicit, anchored rotation."""

    def __init__(
        self,
        directory: str | Path,
        *,
        max_segment_bytes: int,
        hard_max_segment_bytes: int,
        anchor: CheckpointAnchor,
        verify_sealed_on_append: bool = True,
    ) -> None:
        if max_segment_bytes <= 0 or hard_max_segment_bytes <= max_segment_bytes:
            raise ValueError(
                "hard_max_segment_bytes must exceed positive max_segment_bytes"
            )
        self.directory = Path(directory)
        self.max_segment_bytes = max_segment_bytes
        self.hard_max_segment_bytes = hard_max_segment_bytes
        self.anchor = anchor
        self.verify_sealed_on_append = verify_sealed_on_append
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        directory_info = self.directory.lstat()
        if not stat.S_ISDIR(directory_info.st_mode):
            raise EvidenceStoreError("evidence path must be a real directory")
        os.chmod(self.directory, 0o700)
        self.manifest_path = self.directory / _MANIFEST
        self._initialize()

    def append(self, event: SessionEvent) -> EvidenceReceipt:
        with self._locked(exclusive=True) as manifest_fd:
            entries, manifest_head = self._read_manifest(manifest_fd)
            segments = self._reconcile(entries, manifest_fd, manifest_head)
            active = segments[-1]
            if not active.opened or active.retired:
                raise EvidenceIntegrityError("manifest has no active segment")
            try:
                self._verify_chain_and_anchor(segments)
            except CheckpointUnavailableError:
                # The documented soft-limit policy permits local appends while
                # the anchor is unavailable. Rotation is retried after append;
                # the configured hard limit remains fail-closed.
                pass
            payload = _event_payload(event)
            # Idempotency spans every retained segment, not just the active one.
            for sealed_segment in segments[:-1]:
                if sealed_segment.retired:
                    continue
                sealed_data = self._read_segment(
                    self.directory / sealed_segment.file_name, sealed_segment
                )
                _, sealed_index = self._scan_segment(
                    sealed_data,
                    sealed_segment.first_record_number - 1,
                    sealed_segment.start_previous_hash,
                )
                prior = sealed_index.get(event.event_id)
                if prior:
                    number, old_payload, record_hash = prior
                    if old_payload != payload:
                        raise EvidenceEventConflictError(
                            "event_id already exists with a different payload"
                        )
                    return EvidenceReceipt(number, event.event_id, record_hash)
            path = self.directory / active.file_name
            data = self._read_segment(path, active)
            verification, index = self._scan_segment(
                data, active.first_record_number - 1, active.start_previous_hash
            )
            existing = index.get(event.event_id)
            if existing:
                number, old_payload, record_hash = existing
                if old_payload != payload:
                    raise EvidenceEventConflictError(
                        "event_id already exists with a different payload"
                    )
                return EvidenceReceipt(number, event.event_id, record_hash)

            unsigned = {
                "schema_version": SCHEMA_VERSION,
                "previous_hash": verification.head_hash,
                "event": payload,
            }
            record_hash = hashlib.sha256(_canonical_json(unsigned)).hexdigest()
            line = _canonical_json({**unsigned, "record_hash": record_hash}) + b"\n"
            if len(line) > MAX_RECORD_BYTES:
                raise EvidenceStoreError("serialized evidence record exceeds size limit")
            if data and len(data) + len(line) > self.hard_max_segment_bytes:
                raise EvidenceStoreError(
                    "evidence segment hard limit reached; refusing unrecorded event"
                )
            if not data and len(line) > self.hard_max_segment_bytes:
                raise EvidenceStoreError("event exceeds evidence segment hard limit")
            fd = self._open_checked(path, os.O_WRONLY | os.O_APPEND)
            try:
                self._write_all(fd, line)
                os.fsync(fd)
            finally:
                os.close(fd)
            if len(data) + len(line) >= self.max_segment_bytes:
                try:
                    self._rotate_locked(entries, segments, manifest_fd, manifest_head)
                except CheckpointError:
                    # The event is safely recorded. Rotation can be retried on
                    # the next append; the hard limit remains authoritative.
                    pass
            return EvidenceReceipt(
                active.first_record_number + verification.record_count,
                event.event_id,
                record_hash,
            )

    def verify_all(self) -> StoreVerification:
        with self._locked(exclusive=False) as manifest_fd:
            entries, _ = self._read_manifest(manifest_fd)
            segments = self._reconcile(entries, manifest_fd, None, read_only=True)
            return self._verify_chain_and_anchor(segments)

    def _verify_chain_and_anchor(
        self,
        segments: list[_Segment],
        *,
        verify_sealed: bool = True,
    ) -> StoreVerification:
        previous_hash = GENESIS_HASH
        next_number = 1
        total = 0
        seen_event_ids: set[str] = set()
        hashes_by_number: dict[int, str] = {0: GENESIS_HASH}

        for segment in segments:
            if segment.first_record_number != next_number:
                raise EvidenceIntegrityError(
                    "global record numbering is discontinuous"
                )
            if segment.start_previous_hash != previous_hash:
                raise EvidenceIntegrityError("cross-segment hash link mismatch")
            if segment.retired:
                if segment.last_record_number < segment.first_record_number:
                    raise EvidenceIntegrityError("retired segment record range is invalid")
                previous_hash = segment.last_hash
                total = segment.last_record_number
                next_number = total + 1
                hashes_by_number[total] = previous_hash
                continue
            if not segment.opened and not verify_sealed:
                previous_hash = segment.last_hash
                total = segment.last_record_number
                next_number = total + 1
                hashes_by_number[total] = previous_hash
                continue

            data = self._read_segment(
                self.directory / segment.file_name, segment
            )
            result, event_index = self._scan_segment(
                data,
                segment.first_record_number - 1,
                segment.start_previous_hash,
            )
            if seen_event_ids.intersection(event_index):
                raise EvidenceIntegrityError(
                    "duplicate event ID across retained evidence segments"
                )
            seen_event_ids.update(event_index)
            if not segment.opened:
                expected_count = (
                    segment.last_record_number - segment.first_record_number + 1
                )
                if (
                    result.record_count != expected_count
                    or result.head_hash != segment.last_hash
                ):
                    raise EvidenceIntegrityError("sealed segment metadata mismatch")
            for _, (record_number, _, record_hash) in event_index.items():
                hashes_by_number[record_number] = record_hash
            previous_hash = result.head_hash
            total = segment.first_record_number - 1 + result.record_count
            next_number = total + 1

        try:
            checkpoint = self.anchor.read()
        except Exception as exc:
            raise CheckpointUnavailableError(
                "could not read external checkpoint"
            ) from exc
        if checkpoint is None and any(not segment.opened for segment in segments):
            raise CheckpointError(
                "sealed evidence exists without an external checkpoint"
            )
        if checkpoint is not None:
            if checkpoint.record_count > total:
                raise CheckpointError(
                    "evidence is shorter than its external checkpoint"
                )
            expected_hash = hashes_by_number.get(checkpoint.record_count)
            if expected_hash is None or not hmac.compare_digest(
                expected_hash, checkpoint.head_hash
            ):
                raise CheckpointError(
                    "evidence does not match its external checkpoint"
                )
        return StoreVerification(total, previous_hash)

    def retire_oldest_segment(
        self, export_path: str | Path, *, approval_id: str
    ) -> None:
        """Retire the oldest sealed segment after export and checkpoint checks.

        The export must be outside the evidence directory and byte-for-byte
        match the sealed segment. Retirement is operator initiated and never
        scheduled automatically.
        """
        if not approval_id.strip():
            raise ValueError("approval_id must not be empty")
        export = Path(export_path)
        try:
            if export.resolve().is_relative_to(self.directory.resolve()):
                raise EvidenceStoreError("evidence export must be outside the evidence directory")
        except OSError as exc:
            raise EvidenceStoreError("cannot resolve evidence export path") from exc

        with self._locked(exclusive=True) as manifest_fd:
            entries, _ = self._read_manifest(manifest_fd)
            segments = self._reconcile(entries, manifest_fd, None)
            self._verify_chain_and_anchor(segments)
            target = next((item for item in segments if not item.retired), None)
            if target is None or target.opened:
                raise EvidenceStoreError("oldest retained segment is not sealed")
            self._read_segment(self.directory / target.file_name, target)
            try:
                export_fd = os.open(export, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            except OSError as exc:
                raise EvidenceStoreError("cannot open verified segment export") from exc
            try:
                info = os.fstat(export_fd)
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) & 0o077
                ):
                    raise EvidenceStoreError("segment export must be a private regular file")
                chunks = []
                while chunk := os.read(export_fd, 1024 * 1024):
                    chunks.append(chunk)
                exported = b"".join(chunks)
            finally:
                os.close(export_fd)
            export_hash = hashlib.sha256(exported).hexdigest()
            if not hmac.compare_digest(export_hash, target.file_sha256):
                raise EvidenceIntegrityError("export does not match the sealed segment")
            self._scan_segment(
                exported, target.first_record_number - 1, target.start_previous_hash
            )

            checkpoint = self.anchor.read()
            if checkpoint is None:
                raise CheckpointError("external checkpoint has not been initialized")
            if checkpoint.generation < target.checkpoint_generation:
                raise CheckpointError("external checkpoint predates the segment seal")
            # Checkpoints are published at segment boundaries. Require the
            # current anchor to match a retained or retired boundary exactly.
            boundaries = [
                item for item in segments
                if not item.opened and item.last_record_number == checkpoint.record_count
            ]
            if not boundaries or not hmac.compare_digest(
                boundaries[-1].last_hash, checkpoint.head_hash
            ):
                raise CheckpointError(
                    "latest checkpoint does not match a verified segment boundary"
                )

            retirement = {
                "type": "segment_retired",
                "segment_id": target.segment_id,
                "retired_at": datetime.now(UTC).isoformat(),
                "last_record_number": target.last_record_number,
                "last_hash": target.last_hash,
                "export_sha256": export_hash,
                "checkpoint_generation": checkpoint.generation,
                "approval_id": approval_id,
            }
            self._append_manifest(manifest_fd, None, retirement)
            (self.directory / target.file_name).unlink()
            self._fsync_directory()

    def rotate(self) -> None:
        with self._locked(exclusive=True) as manifest_fd:
            entries, manifest_head = self._read_manifest(manifest_fd)
            segments = self._reconcile(entries, manifest_fd, manifest_head)
            active = segments[-1]
            if not active.opened or active.retired:
                raise EvidenceIntegrityError("manifest has no active segment")
            self._verify_chain_and_anchor(segments)
            self._rotate_locked(entries, segments, manifest_fd, manifest_head)

    def _rotate_locked(
        self,
        entries: list[dict[str, Any]],
        segments: list[_Segment],
        manifest_fd: int,
        manifest_head: str | None,
    ) -> None:
        active = segments[-1]
        path = self.directory / active.file_name
        data = self._read_segment(path, active)
        result, _ = self._scan_segment(
            data, active.first_record_number - 1, active.start_previous_hash
        )
        if result.record_count == 0:
            raise EvidenceStoreError("cannot rotate an empty evidence segment")
        global_result = StoreVerification(
            active.first_record_number - 1 + result.record_count,
            result.head_hash,
        )
        checkpoint = self._publish_head(global_result)
        sealed = {
            "type": "segment_sealed",
            "segment_id": active.segment_id,
            "record_count": result.record_count,
            "last_record_number": active.first_record_number + result.record_count - 1,
            "last_hash": result.head_hash,
            "file_size": len(data),
            "file_sha256": hashlib.sha256(data).hexdigest(),
            "checkpoint_generation": checkpoint.generation,
            "sealed_at": datetime.now(UTC).isoformat(),
        }
        self._append_manifest(manifest_fd, manifest_head, sealed)
        os.chmod(path, 0o400)
        fd = self._open_checked(path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        self._fsync_directory()
        next_id = active.segment_id + 1
        next_name = f"segment-{next_id:08d}.jsonl"
        next_path = self.directory / next_name
        opened = {
            "type": "segment_opened",
            "segment_id": next_id,
            "file_name": next_name,
            "first_record_number": sealed["last_record_number"] + 1,
            "start_previous_hash": result.head_hash,
            "opened_at": datetime.now(UTC).isoformat(),
        }
        # Record intent first. If the process crashes before file creation,
        # manifest reconciliation safely creates the missing empty segment.
        self._append_manifest(manifest_fd, None, opened)
        next_fd = os.open(
            next_path,
            os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        os.fsync(next_fd)
        os.close(next_fd)
        self._fsync_directory()

    def _publish_head(self, result: StoreVerification):
        # The anchor contract is the same monotonic CAS used by JsonlEvidenceStore.
        try:
            current = self.anchor.read()
        except Exception as exc:
            raise CheckpointUnavailableError(
                "could not read external checkpoint"
            ) from exc
        generation = 1 if current is None else current.generation + 1
        if current is not None:
            if current.record_count > result.record_count:
                raise CheckpointError("external checkpoint is ahead of local evidence")
            if current.record_count == result.record_count:
                if not hmac.compare_digest(current.head_hash, result.head_hash):
                    raise CheckpointError(
                        "external checkpoint does not match local evidence"
                    )
                return current
        from mirage.telemetry.checkpoints import EvidenceCheckpoint
        checkpoint = EvidenceCheckpoint(generation, result.record_count, result.head_hash)
        try:
            self.anchor.compare_and_set(
                expected_generation=None if current is None else current.generation,
                checkpoint=checkpoint,
            )
        except CheckpointError:
            raise
        except Exception as exc:
            raise CheckpointError("could not publish external checkpoint") from exc
        return checkpoint

    def _initialize(self) -> None:
        with self._locked(exclusive=True) as fd:
            if os.fstat(fd).st_size:
                entries, head = self._read_manifest(fd)
                self._reconcile(entries, fd, head)
                return
            existing = [p.name for p in self.directory.iterdir() if _SEGMENT_RE.match(p.name)]
            if existing:
                raise EvidenceIntegrityError("segment files exist without a manifest entry")
            self._append_manifest(fd, None, {
                "type": "segment_opened", "segment_id": 1,
                "file_name": "segment-00000001.jsonl", "first_record_number": 1,
                "start_previous_hash": GENESIS_HASH, "opened_at": datetime.now(UTC).isoformat(),
            })
            self._fsync_directory()
            path = self.directory / "segment-00000001.jsonl"
            seg_fd = os.open(
                path,
                os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            os.fsync(seg_fd)
            os.close(seg_fd)
            self._fsync_directory()

    def _read_manifest(self, fd: int) -> tuple[list[dict[str, Any]], str]:
        os.lseek(fd, 0, os.SEEK_SET)
        data = b""
        while chunk := os.read(fd, 1024 * 1024):
            data += chunk
        if not data or not data.endswith(b"\n"):
            raise EvidenceIntegrityError("manifest is empty or has an incomplete trailing entry")
        previous = GENESIS_HASH
        entries = []
        for number, line in enumerate(data.splitlines(), 1):
            try:
                envelope = json.loads(line, object_pairs_hook=_reject_duplicate_keys)
            except (json.JSONDecodeError, EvidenceIntegrityError) as exc:
                raise EvidenceIntegrityError(f"invalid manifest entry {number}") from exc
            expected_keys = {
                "schema_version", "previous_manifest_hash", "entry", "entry_hash"
            }
            if not isinstance(envelope, dict) or set(envelope) != expected_keys:
                raise EvidenceIntegrityError(f"invalid manifest envelope at entry {number}")
            if envelope["schema_version"] != 1 or envelope["previous_manifest_hash"] != previous:
                raise EvidenceIntegrityError(f"manifest chain mismatch at entry {number}")
            unsigned = {
                key: envelope[key]
                for key in ("schema_version", "previous_manifest_hash", "entry")
            }
            expected = hashlib.sha256(_canonical_json(unsigned)).hexdigest()
            if not isinstance(envelope["entry_hash"], str) or not hmac.compare_digest(
                expected, envelope["entry_hash"]
            ):
                raise EvidenceIntegrityError(f"manifest hash mismatch at entry {number}")
            if not isinstance(envelope["entry"], dict):
                raise EvidenceIntegrityError(f"invalid manifest payload at entry {number}")
            previous = expected
            entries.append(envelope["entry"])
        return entries, previous

    def _append_manifest(self, fd: int, previous: str | None, entry: dict[str, Any]) -> str:
        # Re-read after each append so a preceding step in the same locked
        # transaction is always reflected in the next link.
        _, head = self._read_manifest(fd) if os.fstat(fd).st_size else ([], GENESIS_HASH)
        unsigned = {"schema_version": 1, "previous_manifest_hash": head, "entry": entry}
        digest = hashlib.sha256(_canonical_json(unsigned)).hexdigest()
        line = _canonical_json({**unsigned, "entry_hash": digest}) + b"\n"
        os.lseek(fd, 0, os.SEEK_END)
        self._write_all(fd, line)
        os.fsync(fd)
        return digest

    def _reconcile(
        self,
        entries: list[dict[str, Any]],
        manifest_fd: int,
        manifest_head: str | None,
        *,
        read_only: bool = False,
    ) -> list[_Segment]:
        states: dict[int, dict[str, Any]] = {}
        for entry in entries:
            kind = entry.get("type")
            sid = entry.get("segment_id")
            if not isinstance(sid, int) or isinstance(sid, bool) or sid < 1:
                raise EvidenceIntegrityError("manifest segment ID is invalid")
            state = states.setdefault(sid, {})
            if kind == "segment_opened":
                if state:
                    raise EvidenceIntegrityError("segment opened more than once")
                state.update(entry)
            elif kind == "segment_sealed":
                if not state or state.get("sealed"):
                    raise EvidenceIntegrityError("unexpected segment seal entry")
                state["sealed"] = entry
            elif kind == "segment_retired":
                if not state.get("sealed") or state.get("retired"):
                    raise EvidenceIntegrityError("unexpected segment retirement entry")
                state["retired"] = entry
            else:
                raise EvidenceIntegrityError("unknown manifest entry type")
        if not states or sorted(states) != list(range(1, max(states) + 1)):
            raise EvidenceIntegrityError("segment IDs are not contiguous")
        segments = []
        for sid in sorted(states):
            state = states[sid]
            expected_name = f"segment-{sid:08d}.jsonl"
            if state.get("file_name") != expected_name:
                raise EvidenceIntegrityError("segment file name is invalid")
            first_number = state.get("first_record_number")
            start_hash = state.get("start_previous_hash")
            if (
                not isinstance(first_number, int)
                or isinstance(first_number, bool)
                or first_number < 1
                or not isinstance(start_hash, str)
                or not re.fullmatch(r"[0-9a-f]{64}", start_hash)
            ):
                raise EvidenceIntegrityError("segment opening metadata is invalid")
            sealed = state.get("sealed", {})
            retired = bool(state.get("retired"))
            segment = _Segment(
                sid, state["file_name"], state["first_record_number"],
                state["start_previous_hash"], not bool(sealed), sealed.get("record_count", 0),
                sealed.get("last_record_number", 0),
                sealed.get("last_hash", state["start_previous_hash"]),
                sealed.get("file_size", 0), sealed.get("file_sha256", ""),
                sealed.get("checkpoint_generation", 0), retired,
                state.get("retired", {}).get("export_sha256", ""),
            )
            path = self.directory / segment.file_name
            if retired and not path.exists():
                segments.append(segment)
                continue
            if not path.exists():
                if sealed or read_only:
                    raise EvidenceIntegrityError("manifest segment file is missing")
                fd = os.open(
                    path,
                    os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                )
                os.fsync(fd)
                os.close(fd)
                self._fsync_directory()
            data = self._read_segment(path, segment)
            if sealed:
                actual_hash = hashlib.sha256(data).hexdigest()
                if len(data) != segment.file_size or not hmac.compare_digest(
                    actual_hash, segment.file_sha256
                ):
                    raise EvidenceIntegrityError("sealed segment size or digest mismatch")
                if not retired and not read_only:
                    os.chmod(path, 0o400)
                    sealed_fd = self._open_checked(path, os.O_RDONLY)
                    try:
                        os.fsync(sealed_fd)
                    finally:
                        os.close(sealed_fd)
            elif data and not read_only:
                self._scan_segment(
                    data, segment.first_record_number - 1, segment.start_previous_hash
                )
            segments.append(segment)
        previous_number = 0
        previous_hash = GENESIS_HASH
        retired_prefix_ended = False
        for index, segment in enumerate(segments):
            if segment.first_record_number != previous_number + 1:
                raise EvidenceIntegrityError("global segment record numbering is discontinuous")
            if segment.start_previous_hash != previous_hash:
                raise EvidenceIntegrityError("segment manifest hash links are discontinuous")
            if segment.retired:
                if retired_prefix_ended:
                    raise EvidenceIntegrityError(
                        "retired segments must form an oldest-first prefix"
                    )
            else:
                retired_prefix_ended = True
            if segment.opened and index != len(segments) - 1:
                raise EvidenceIntegrityError("only the newest segment may be active")
            if index == len(segments) - 1 and not segment.opened and read_only:
                raise EvidenceIntegrityError("manifest has no active segment")
            if not segment.opened:
                previous_number = segment.last_record_number
                previous_hash = segment.last_hash
        expected_files = {
            segment.file_name
            for segment in segments
            if not segment.retired or (self.directory / segment.file_name).exists()
        }
        for path in self.directory.iterdir():
            if _SEGMENT_RE.match(path.name) and path.name not in expected_files:
                raise EvidenceIntegrityError("unmanifested segment file exists")
        if not read_only and segments and segments[-1].opened is False:
            # Crash after seal but before successor open: complete the recorded transition.
            last = segments[-1]
            next_id = last.segment_id + 1
            name = f"segment-{next_id:08d}.jsonl"
            self._append_manifest(manifest_fd, None, {
                "type": "segment_opened", "segment_id": next_id, "file_name": name,
                "first_record_number": last.last_record_number + 1,
                "start_previous_hash": last.last_hash, "opened_at": datetime.now(UTC).isoformat(),
            })
            fd = os.open(
                self.directory / name,
                os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            os.fsync(fd)
            os.close(fd)
            self._fsync_directory()
            return self._reconcile(self._read_manifest(manifest_fd)[0], manifest_fd, None)
        return segments

    def _verify_sealed(self, segments: list[_Segment]) -> None:
        previous = GENESIS_HASH
        next_number = 1
        for segment in segments:
            if segment.retired:
                previous = segment.last_hash
                next_number = segment.last_record_number + 1
                continue
            data = self._read_segment(self.directory / segment.file_name, segment)
            result, _ = self._scan_segment(
                data, segment.first_record_number - 1, segment.start_previous_hash
            )
            if (
                result.head_hash != segment.last_hash
                or segment.start_previous_hash != previous
                or segment.first_record_number != next_number
            ):
                raise EvidenceIntegrityError("sealed segment chain verification failed")
            previous = result.head_hash
            next_number = segment.last_record_number + 1

    def _read_segment(self, path: Path, segment: _Segment) -> bytes:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise EvidenceStoreError("segment must be a regular file without hard links")
            if stat.S_IMODE(info.st_mode) & 0o077:
                raise EvidenceStoreError("segment permissions must be private")
            chunks = []
            while chunk := os.read(fd, 1024 * 1024):
                chunks.append(chunk)
            return b"".join(chunks)
        finally:
            os.close(fd)

    def _scan_segment(self, data: bytes, prior_count: int, start_hash: str):
        if data and not data.endswith(b"\n"):
            raise EvidenceIntegrityError("segment has an incomplete trailing record")
        previous = start_hash
        count = 0
        index: dict[str, tuple[int, dict[str, Any], str]] = {}
        for line_number, line in enumerate(data.splitlines(), 1):
            if not line or len(line) + 1 > MAX_RECORD_BYTES:
                raise EvidenceIntegrityError(
                    f"segment record {line_number} is empty or exceeds the size limit"
                )
            try:
                envelope = json.loads(line, object_pairs_hook=_reject_duplicate_keys)
            except (json.JSONDecodeError, EvidenceIntegrityError) as exc:
                raise EvidenceIntegrityError(f"invalid segment record {line_number}") from exc
            expected_keys = {
                "schema_version", "previous_hash", "event", "record_hash"
            }
            if not isinstance(envelope, dict) or set(envelope) != expected_keys:
                raise EvidenceIntegrityError("invalid segment record envelope")
            if (
                envelope["schema_version"] != SCHEMA_VERSION
                or envelope["previous_hash"] != previous
            ):
                raise EvidenceIntegrityError("segment hash-chain link mismatch")
            event = envelope["event"]
            if (
                not isinstance(event, dict)
                or not isinstance(event.get("event_id"), str)
                or not event["event_id"].strip()
            ):
                raise EvidenceIntegrityError("invalid segment event")
            event_id = event["event_id"]
            if event_id in index:
                raise EvidenceIntegrityError("duplicate event ID in segment")
            unsigned = {k: envelope[k] for k in ("schema_version", "previous_hash", "event")}
            digest = hashlib.sha256(_canonical_json(unsigned)).hexdigest()
            if not isinstance(envelope["record_hash"], str) or not hmac.compare_digest(
                digest, envelope["record_hash"]
            ):
                raise EvidenceIntegrityError("segment record hash mismatch")
            previous = digest
            count += 1
            index[event_id] = (prior_count + count, event, digest)
        return StoreVerification(count, previous), index

    @staticmethod
    def _open_checked(path: Path, flags: int) -> int:
        fd = os.open(path, flags | getattr(os, "O_NOFOLLOW", 0))
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            os.close(fd)
            raise EvidenceStoreError("unsafe evidence file")
        return fd

    @staticmethod
    def _write_all(fd: int, data: bytes) -> None:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short evidence write")
            view = view[written:]

    def _locked(self, *, exclusive: bool):
        class LockContext:
            def __init__(inner, store):
                inner.store = store
                inner.fd = -1
            def __enter__(inner):
                flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
                inner.fd = os.open(inner.store.manifest_path, flags, 0o600)
                info = os.fstat(inner.fd)
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) & 0o077
                ):
                    os.close(inner.fd)
                    raise EvidenceStoreError("unsafe manifest file")
                fcntl.flock(inner.fd, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
                return inner.fd
            def __exit__(inner, exc_type, exc, tb):
                os.close(inner.fd)
        return LockContext(self)

    def _fsync_directory(self) -> None:
        fd = os.open(self.directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
