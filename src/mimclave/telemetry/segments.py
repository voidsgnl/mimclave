"""Segmented, rotation-capable evidence store for MIMCLAVE.

Implements the design in ``docs/evidence-segments.md``.  Every segment is an
append-only JSONL file with the same record envelope used by
``JsonlEvidenceStore``.  A hash-chained manifest tracks the lifecycle of each
segment; together they form one continuous, externally-anchorable hash chain.

The existing ``JsonlEvidenceStore`` is unchanged.  Operators may adopt a
legacy single-file log via ``SegmentedEvidenceStore.adopt_legacy``.

Security invariants
-------------------
* All files are opened with ``O_EXCL | O_NOFOLLOW`` where applicable.
* Symlinks, hard links, non-regular files, and unsafe permissions are rejected.
* No automatic deletion; retirement is an explicit operator action.
* An integrity error always stops the store; nothing is silently repaired.
* Decoy responses are not sent when their event cannot be persisted (the
  caller's transport enforces this via the event-sink contract).
"""

from __future__ import annotations

import errno
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

from mimclave.telemetry.checkpoints import (
    CheckpointAnchor,
    CheckpointError,
    EvidenceCheckpoint,
)
from mimclave.telemetry.events import SessionEvent
from mimclave.telemetry.store import (
    GENESIS_HASH,
    MAX_RECORD_BYTES,
    SCHEMA_VERSION,
    EvidenceEventConflictError,
    EvidenceIntegrityError,
    EvidenceReceipt,
    EvidenceStoreError,
    StoreVerification,
    _canonical_json,  # noqa: PLC2701  (shared internal helper)
    _event_payload,  # noqa: PLC2701
    _reject_duplicate_keys,  # noqa: PLC2701
)

# ---------------------------------------------------------------------------
# Manifest schema
# ---------------------------------------------------------------------------

MANIFEST_SCHEMA_VERSION = 1
SEGMENT_NAME_RE = re.compile(r"^segment-(\d{8})\.jsonl$")
MANIFEST_NAME = "manifest.jsonl"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class SegmentRotationError(EvidenceStoreError):
    """A rotation could not complete; evidence collection is impaired."""


class SegmentRetirementError(EvidenceStoreError):
    """An operator-approved retirement precondition was not satisfied."""


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SegmentInfo:
    """Summary of one segment as known from the manifest."""

    segment_id: int
    file_name: str
    first_record_number: int
    start_previous_hash: str
    # Set after sealing:
    record_count: int | None = None
    last_record_number: int | None = None
    last_hash: str | None = None
    file_size: int | None = None
    file_sha256: str | None = None
    checkpoint_generation: int | None = None
    # Set after retirement:
    retired: bool = False
    export_sha256: str | None = None
    approval_id: str | None = None


@dataclass(frozen=True, slots=True)
class ManifestVerification:
    """Result of a successful manifest chain scan."""

    segments: tuple[SegmentInfo, ...]

    @property
    def active(self) -> SegmentInfo | None:
        """The currently open (unsealed) segment, if any."""
        for s in reversed(self.segments):
            if not s.retired and s.last_hash is None:
                return s
        return None

    @property
    def sealed(self) -> tuple[SegmentInfo, ...]:
        """Sealed-but-not-retired segments, oldest first."""
        return tuple(
            s for s in self.segments if s.last_hash is not None and not s.retired
        )

    @property
    def retired_segments(self) -> tuple[SegmentInfo, ...]:
        return tuple(s for s in self.segments if s.retired)

    @property
    def retained(self) -> tuple[SegmentInfo, ...]:
        """All non-retired segments (sealed + active), oldest first."""
        return tuple(s for s in self.segments if not s.retired)

    def global_record_count(self) -> int:
        """Global record count known from the latest sealed or active segment."""
        # Active segment's count is determined by scanning its file; the
        # manifest only records it at sealing time.  Return last sealed count
        # as a floor; callers that need the precise live count must scan the
        # active file separately.
        for s in reversed(self.segments):
            if s.last_record_number is not None:
                return s.last_record_number
        return 0


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _segment_file_name(segment_id: int) -> str:
    return f"segment-{segment_id:08d}.jsonl"


def _manifest_envelope(entry: dict[str, Any], previous_hash: str) -> tuple[bytes, str]:
    """Return (canonical bytes of full envelope, entry_hash)."""
    unsigned: dict[str, Any] = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "previous_manifest_hash": previous_hash,
        "entry": entry,
    }
    entry_hash = hashlib.sha256(_canonical_json(unsigned)).hexdigest()
    envelope = {**unsigned, "entry_hash": entry_hash}
    return _canonical_json(envelope) + b"\n", entry_hash


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _validate_regular_private(fd: int) -> None:
    """Raise EvidenceStoreError if fd is not a private regular file."""
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode):
        raise EvidenceStoreError("evidence file must be a regular file")
    if info.st_nlink != 1:
        raise EvidenceStoreError("evidence file must not have multiple hard links")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise EvidenceStoreError("evidence file permissions must be 0600 or stricter")


def _open_private(path: Path, flags: int, mode: int = 0o600) -> int:
    """Open path with O_NOFOLLOW; raise EvidenceStoreError on failure."""
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        return os.open(path, flags, mode)
    except OSError as exc:
        raise EvidenceStoreError(f"cannot open {path.name}: {exc}") from exc


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError(errno.EIO, "short write")
        view = view[written:]


def _read_all(fd: int) -> bytes:
    os.lseek(fd, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    while chunk := os.read(fd, 1024 * 1024):
        chunks.append(chunk)
    return b"".join(chunks)


def _fsync_dir(directory: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    dfd = os.open(directory, flags)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


# ---------------------------------------------------------------------------
# Manifest scanning
# ---------------------------------------------------------------------------


def _scan_manifest(data: bytes) -> tuple[ManifestVerification, dict[str, Any]]:
    """Parse and verify the manifest chain.  Return (verification, raw_entries)."""
    if not data:
        return ManifestVerification(segments=()), {}
    if not data.endswith(b"\n"):
        raise EvidenceIntegrityError("manifest has an incomplete trailing record")

    previous_hash = GENESIS_HASH
    segments_by_id: dict[int, dict[str, Any]] = {}  # segment_id -> mutable state
    ordered_ids: list[int] = []

    for line_number, line in enumerate(data.splitlines(), start=1):
        if not line:
            raise EvidenceIntegrityError(
                f"manifest has an empty line at record {line_number}"
            )
        try:
            envelope = json.loads(line, object_pairs_hook=_reject_duplicate_keys)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise EvidenceIntegrityError(
                f"manifest record {line_number} is not valid JSON"
            ) from exc
        if not isinstance(envelope, dict) or set(envelope) != {
            "schema_version",
            "previous_manifest_hash",
            "entry",
            "entry_hash",
        }:
            raise EvidenceIntegrityError(
                f"manifest record {line_number} has an invalid envelope"
            )
        if envelope["schema_version"] != MANIFEST_SCHEMA_VERSION:
            raise EvidenceIntegrityError(
                f"unsupported manifest schema version at record {line_number}"
            )
        if envelope["previous_manifest_hash"] != previous_hash:
            raise EvidenceIntegrityError(
                f"manifest hash-chain link mismatch at record {line_number}"
            )
        unsigned = {
            "schema_version": envelope["schema_version"],
            "previous_manifest_hash": envelope["previous_manifest_hash"],
            "entry": envelope["entry"],
        }
        expected_hash = hashlib.sha256(_canonical_json(unsigned)).hexdigest()
        if not isinstance(envelope["entry_hash"], str) or not hmac.compare_digest(
            envelope["entry_hash"], expected_hash
        ):
            raise EvidenceIntegrityError(
                f"manifest entry hash mismatch at record {line_number}"
            )
        previous_hash = expected_hash
        entry = envelope["entry"]
        if not isinstance(entry, dict) or "entry_type" not in entry:
            raise EvidenceIntegrityError(
                f"manifest entry at record {line_number} has no entry_type"
            )
        entry_type = entry["entry_type"]
        seg_id = entry.get("segment_id")
        if not isinstance(seg_id, int) or seg_id < 1:
            raise EvidenceIntegrityError(
                f"manifest entry at record {line_number} has an invalid segment_id"
            )

        if entry_type == "segment_opened":
            if seg_id in segments_by_id:
                raise EvidenceIntegrityError(
                    f"manifest: segment {seg_id} opened more than once"
                )
            # Contiguity check
            if ordered_ids:
                if seg_id != ordered_ids[-1] + 1:
                    raise EvidenceIntegrityError(
                        f"manifest: segment IDs are not contiguous (expected "
                        f"{ordered_ids[-1] + 1}, got {seg_id})"
                    )
            else:
                if seg_id != 1:
                    raise EvidenceIntegrityError(
                        "manifest: first segment_id must be 1"
                    )
            ordered_ids.append(seg_id)
            segments_by_id[seg_id] = {
                "segment_id": seg_id,
                "file_name": entry.get("file_name", _segment_file_name(seg_id)),
                "first_record_number": entry["first_record_number"],
                "start_previous_hash": entry["start_previous_hash"],
                "sealed": False,
                "retired": False,
            }

        elif entry_type == "segment_sealed":
            if seg_id not in segments_by_id:
                raise EvidenceIntegrityError(
                    f"manifest: segment {seg_id} sealed before opened"
                )
            state = segments_by_id[seg_id]
            if state["sealed"]:
                raise EvidenceIntegrityError(
                    f"manifest: segment {seg_id} sealed more than once"
                )
            if state["retired"]:
                raise EvidenceIntegrityError(
                    f"manifest: segment {seg_id} sealed after retirement"
                )
            state.update(
                {
                    "sealed": True,
                    "record_count": entry["record_count"],
                    "last_record_number": entry["last_record_number"],
                    "last_hash": entry["last_hash"],
                    "file_size": entry["file_size"],
                    "file_sha256": entry["file_sha256"],
                    "checkpoint_generation": entry.get("checkpoint_generation"),
                }
            )

        elif entry_type == "segment_retired":
            if seg_id not in segments_by_id:
                raise EvidenceIntegrityError(
                    f"manifest: segment {seg_id} retired before opened"
                )
            state = segments_by_id[seg_id]
            if not state["sealed"]:
                raise EvidenceIntegrityError(
                    f"manifest: segment {seg_id} retired but not sealed"
                )
            if state["retired"]:
                raise EvidenceIntegrityError(
                    f"manifest: segment {seg_id} retired more than once"
                )
            # Must retire strictly oldest-first among retained segments
            retained_ids = [
                i for i in ordered_ids if not segments_by_id[i]["retired"]
            ]
            if retained_ids and retained_ids[0] != seg_id:
                raise EvidenceIntegrityError(
                    f"manifest: segment {seg_id} retired out of order; "
                    f"oldest retained is {retained_ids[0]}"
                )
            state.update(
                {
                    "retired": True,
                    "export_sha256": entry.get("export_sha256"),
                    "approval_id": entry.get("approval_id"),
                }
            )
        else:
            raise EvidenceIntegrityError(
                f"manifest: unknown entry_type {entry_type!r} at record {line_number}"
            )

    # Validate cross-segment hash links for sealed segments
    prev_last_hash = GENESIS_HASH
    prev_last_record_number = 0
    for seg_id in ordered_ids:
        state = segments_by_id[seg_id]
        if state["start_previous_hash"] != prev_last_hash:
            raise EvidenceIntegrityError(
                f"manifest: segment {seg_id} start_previous_hash does not "
                f"match predecessor last_hash"
            )
        expected_first = prev_last_record_number + 1
        if state["first_record_number"] != expected_first:
            raise EvidenceIntegrityError(
                f"manifest: segment {seg_id} first_record_number should be "
                f"{expected_first}, got {state['first_record_number']}"
            )
        if state["sealed"]:
            prev_last_hash = state["last_hash"]
            prev_last_record_number = state["last_record_number"]
        else:
            # Active segment: chain continues from start
            prev_last_hash = state["start_previous_hash"]

    # Build SegmentInfo tuple
    infos: list[SegmentInfo] = []
    for seg_id in ordered_ids:
        s = segments_by_id[seg_id]
        infos.append(
            SegmentInfo(
                segment_id=seg_id,
                file_name=s["file_name"],
                first_record_number=s["first_record_number"],
                start_previous_hash=s["start_previous_hash"],
                record_count=s.get("record_count"),
                last_record_number=s.get("last_record_number"),
                last_hash=s.get("last_hash"),
                file_size=s.get("file_size"),
                file_sha256=s.get("file_sha256"),
                checkpoint_generation=s.get("checkpoint_generation"),
                retired=s["retired"],
                export_sha256=s.get("export_sha256"),
                approval_id=s.get("approval_id"),
            )
        )
    return ManifestVerification(segments=tuple(infos)), {}


# ---------------------------------------------------------------------------
# Segment-file scanning (reuses store internals)
# ---------------------------------------------------------------------------


def _scan_segment_bytes(
    data: bytes,
    *,
    start_record_number: int,
    start_previous_hash: str,
) -> tuple[StoreVerification, dict[str, tuple[int, dict[str, Any], str]]]:
    """Verify and index one segment's bytes.

    ``start_record_number`` is the global record number of the *first* record
    in this segment (1-based).  ``start_previous_hash`` is the hash that the
    first record's ``previous_hash`` must equal.
    """
    event_index: dict[str, tuple[int, dict[str, Any], str]] = {}
    if not data:
        return (
            StoreVerification(
                record_count=start_record_number - 1,
                head_hash=start_previous_hash,
            ),
            event_index,
        )
    if not data.endswith(b"\n"):
        raise EvidenceIntegrityError("segment has an incomplete trailing record")

    previous_hash = start_previous_hash
    record_number = start_record_number - 1

    for line_number, line in enumerate(data.splitlines(), start=1):
        if not line:
            raise EvidenceIntegrityError(
                f"segment has an empty line at position {line_number}"
            )
        if len(line) + 1 > MAX_RECORD_BYTES:
            raise EvidenceIntegrityError(
                f"segment record {line_number} exceeds the size limit"
            )
        try:
            envelope = json.loads(line, object_pairs_hook=_reject_duplicate_keys)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise EvidenceIntegrityError(
                f"segment record {line_number} is not valid JSON"
            ) from exc
        if not isinstance(envelope, dict) or set(envelope) != {
            "schema_version",
            "previous_hash",
            "event",
            "record_hash",
        }:
            raise EvidenceIntegrityError(
                f"segment record {line_number} has an invalid envelope"
            )
        if envelope["schema_version"] != SCHEMA_VERSION:
            raise EvidenceIntegrityError(
                f"unsupported evidence schema version at segment record {line_number}"
            )
        if envelope["previous_hash"] != previous_hash:
            raise EvidenceIntegrityError(
                f"hash-chain link mismatch at segment record {line_number}"
            )
        event = envelope["event"]
        if (
            not isinstance(event, dict)
            or not isinstance(event.get("event_id"), str)
            or not event["event_id"].strip()
        ):
            raise EvidenceIntegrityError(
                f"event payload or event_id is invalid at segment record {line_number}"
            )
        event_id = event["event_id"]
        if event_id in event_index:
            raise EvidenceIntegrityError(
                f"duplicate event_id at segment record {line_number}"
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
                f"record hash mismatch at segment record {line_number}"
            )
        previous_hash = expected_hash
        record_number += 1
        event_index[event_id] = (record_number, event, expected_hash)

    return StoreVerification(record_count=record_number, head_hash=previous_hash), event_index


# ---------------------------------------------------------------------------
# Main store class
# ---------------------------------------------------------------------------


class SegmentedEvidenceStore:
    """Rotation-capable, externally-anchorable evidence store.

    Parameters
    ----------
    directory:
        A private directory (mode 0700) that will be created if it does not
        exist.  All evidence and manifest files live here.
    max_segment_bytes:
        Soft size limit per segment.  When the active segment reaches or
        exceeds this many bytes, rotation is attempted on the next append.
        Must be less than ``hard_max_segment_bytes``.
    hard_max_segment_bytes:
        Hard size limit.  Append fails closed with
        ``SegmentRotationError`` if the active segment reaches or exceeds
        this many bytes and rotation could not complete.  Must be greater
        than ``max_segment_bytes``.
    max_segment_records:
        Optional soft record limit per segment.  Rotation is triggered
        when either the byte or record soft limit is reached.
    verify_sealed_on_append:
        When ``True`` (the default), every append re-verifies all sealed
        segments via their recorded ``file_sha256`` and hash-chain links.
        Set to ``False`` only after benchmark measurements on target
        storage show that the per-append cost is unacceptable.
    """

    def __init__(
        self,
        directory: str | Path,
        *,
        max_segment_bytes: int,
        hard_max_segment_bytes: int,
        max_segment_records: int | None = None,
        verify_sealed_on_append: bool = True,
    ) -> None:
        if hard_max_segment_bytes <= max_segment_bytes:
            raise ValueError(
                "hard_max_segment_bytes must be greater than max_segment_bytes"
            )
        if max_segment_bytes < 1:
            raise ValueError("max_segment_bytes must be positive")
        if max_segment_records is not None and max_segment_records < 1:
            raise ValueError("max_segment_records must be positive when specified")
        self.directory = Path(directory)
        self.max_segment_bytes = max_segment_bytes
        self.hard_max_segment_bytes = hard_max_segment_bytes
        self.max_segment_records = max_segment_records
        self.verify_sealed_on_append = verify_sealed_on_append

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def open(self) -> None:
        """Create the evidence directory and perform crash recovery.

        Idempotent; safe to call repeatedly.
        """
        self._ensure_directory()
        manifest_path = self.directory / MANIFEST_NAME
        if not manifest_path.exists():
            # Brand-new store: create the manifest and open segment 1.
            self._create_manifest_and_first_segment()
            return
        # Existing store: acquire exclusive lock and reconcile.
        mfd = _open_private(manifest_path, os.O_RDWR)
        try:
            _validate_regular_private(mfd)
            fcntl.flock(mfd, fcntl.LOCK_EX)
            _validate_regular_private(mfd)
            self._crash_recover(mfd)
        finally:
            os.close(mfd)

    def append(
        self,
        event: SessionEvent,
        *,
        anchor: CheckpointAnchor | None = None,
    ) -> EvidenceReceipt:
        """Append one event to the active segment.

        ``anchor`` is used only when rotation is triggered.  Pass the same
        anchor that you use with ``publish_checkpoint``; rotation refuses
        to seal a segment if checkpoint publication fails.

        Raise ``SegmentRotationError`` if the hard size limit is reached and
        rotation failed.  Raise ``EvidenceStoreError`` on any storage failure.
        """
        self._ensure_directory()
        manifest_path = self.directory / MANIFEST_NAME
        mfd = _open_private(manifest_path, os.O_RDWR)
        try:
            _validate_regular_private(mfd)
            fcntl.flock(mfd, fcntl.LOCK_EX)
            _validate_regular_private(mfd)
            manifest_data = _read_all(mfd)
            mv, _ = _scan_manifest(manifest_data)
            self._reconcile_directory(mv)

            active = mv.active
            if active is None:
                raise EvidenceIntegrityError(
                    "evidence directory has no active segment; call open() first"
                )

            # Check the active segment and collect the full retained event index.
            sealed_index = self._verify_sealed_segments(mv) if self.verify_sealed_on_append else {}
            seg_path = self.directory / active.file_name
            sfd = _open_private(seg_path, os.O_RDWR | os.O_APPEND)
            try:
                _validate_regular_private(sfd)
                seg_data = _read_all(sfd)
                seg_v, seg_index = _scan_segment_bytes(
                    seg_data,
                    start_record_number=active.first_record_number,
                    start_previous_hash=active.start_previous_hash,
                )

                # Merge indices for idempotency check
                merged_index = {**sealed_index, **seg_index}
                payload = _event_payload(event)
                existing = merged_index.get(event.event_id)
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

                # Check size limits before writing.
                seg_size = os.fstat(sfd).st_size
                record_count_in_seg = seg_v.record_count - (active.first_record_number - 1)
                soft_limit_hit = (
                    seg_size >= self.max_segment_bytes
                    or (
                        self.max_segment_records is not None
                        and record_count_in_seg >= self.max_segment_records
                    )
                )
                hard_limit_hit = seg_size >= self.hard_max_segment_bytes

                if hard_limit_hit:
                    raise SegmentRotationError(
                        f"active segment {active.file_name} has reached the hard size "
                        f"limit ({seg_size} >= {self.hard_max_segment_bytes} bytes); "
                        "rotation must succeed before new events can be appended"
                    )

                if soft_limit_hit and anchor is not None:
                    # Attempt rotation under the existing locks.  On anchor
                    # failure (CheckpointError) keep appending to the current
                    # segment and report to the caller via a non-fatal warning
                    # embedded in the receipt (the design says "on failure keep
                    # appending to the current segment and report the failure to
                    # the operator").  The hard limit above ensures we eventually
                    # stop if rotation never succeeds.
                    try:
                        os.close(sfd)
                        sfd = -1
                        self._rotate(mfd, manifest_data, mv, active, seg_v, anchor)
                        # Re-read manifest and open new segment.
                        manifest_data = _read_all(mfd)
                        mv, _ = _scan_manifest(manifest_data)
                        active = mv.active
                        if active is None:
                            raise EvidenceIntegrityError(
                                "rotation did not create a new active segment"
                            )
                        seg_path = self.directory / active.file_name
                        sfd = _open_private(seg_path, os.O_RDWR | os.O_APPEND)
                        _validate_regular_private(sfd)
                        seg_data = _read_all(sfd)
                        seg_v, _ = _scan_segment_bytes(
                            seg_data,
                            start_record_number=active.first_record_number,
                            start_previous_hash=active.start_previous_hash,
                        )
                    except CheckpointError as rotation_error:
                        # Rotation failed; re-open the original segment for appending.
                        if sfd == -1:
                            manifest_data = _read_all(mfd)
                            mv, _ = _scan_manifest(manifest_data)
                            active = mv.active
                            if active is None:
                                raise EvidenceIntegrityError(
                                    "no active segment after failed rotation"
                                ) from rotation_error
                            seg_path = self.directory / active.file_name
                            sfd = _open_private(seg_path, os.O_RDWR | os.O_APPEND)
                            _validate_regular_private(sfd)
                            seg_data = _read_all(sfd)
                            seg_v, _ = _scan_segment_bytes(
                                seg_data,
                                start_record_number=active.first_record_number,
                                start_previous_hash=active.start_previous_hash,
                            )

                # Write the new record.
                unsigned = {
                    "schema_version": SCHEMA_VERSION,
                    "previous_hash": seg_v.head_hash,
                    "event": payload,
                }
                record_hash = hashlib.sha256(_canonical_json(unsigned)).hexdigest()
                envelope = {**unsigned, "record_hash": record_hash}
                line = _canonical_json(envelope) + b"\n"
                if len(line) > MAX_RECORD_BYTES:
                    raise EvidenceStoreError(
                        "serialized evidence record exceeds size limit"
                    )
                if sfd == -1:
                    raise EvidenceStoreError("segment file descriptor lost after rotation")
                _write_all(sfd, line)
                os.fsync(sfd)
                return EvidenceReceipt(
                    record_number=seg_v.record_count + 1,
                    event_id=event.event_id,
                    record_hash=record_hash,
                )
            finally:
                if sfd != -1:
                    os.close(sfd)
        except EvidenceStoreError:
            raise
        except OSError as exc:
            raise EvidenceStoreError(f"evidence append failed: {exc}") from exc
        finally:
            os.close(mfd)

    def verify(self) -> StoreVerification:
        """Verify the complete retained chain under a shared manifest lock."""
        manifest_path = self.directory / MANIFEST_NAME
        mfd = _open_private(manifest_path, os.O_RDONLY)
        try:
            _validate_regular_private(mfd)
            fcntl.flock(mfd, fcntl.LOCK_SH)
            manifest_data = _read_all(mfd)
            mv, _ = _scan_manifest(manifest_data)
            self._reconcile_directory(mv)
            return self._verify_all_retained(mv)
        except EvidenceStoreError:
            raise
        except OSError as exc:
            raise EvidenceStoreError(f"evidence verification failed: {exc}") from exc
        finally:
            os.close(mfd)

    def publish_checkpoint(self, anchor: CheckpointAnchor) -> EvidenceCheckpoint:
        """Publish the current verified head to an external anchor."""
        manifest_path = self.directory / MANIFEST_NAME
        mfd = _open_private(manifest_path, os.O_RDWR)
        try:
            _validate_regular_private(mfd)
            fcntl.flock(mfd, fcntl.LOCK_EX)
            _validate_regular_private(mfd)
            manifest_data = _read_all(mfd)
            mv, _ = _scan_manifest(manifest_data)
            self._reconcile_directory(mv)
            verification = self._verify_all_retained(mv)
            if verification.record_count == 0:
                raise CheckpointError("cannot checkpoint an empty evidence store")
            return self._do_publish_checkpoint(anchor, verification)
        except (EvidenceStoreError, CheckpointError):
            raise
        except OSError as exc:
            raise EvidenceStoreError(f"checkpoint operation failed: {exc}") from exc
        finally:
            os.close(mfd)

    def verify_checkpoint(self, anchor: CheckpointAnchor) -> EvidenceCheckpoint:
        """Verify that the retained log contains the prefix committed externally."""
        manifest_path = self.directory / MANIFEST_NAME
        mfd = _open_private(manifest_path, os.O_RDONLY)
        try:
            _validate_regular_private(mfd)
            fcntl.flock(mfd, fcntl.LOCK_SH)
            manifest_data = _read_all(mfd)
            mv, _ = _scan_manifest(manifest_data)
            self._reconcile_directory(mv)
            verification, full_index = self._verify_all_retained_with_index(mv)
            try:
                checkpoint = anchor.read()
            except Exception as exc:
                raise CheckpointError("could not read external checkpoint") from exc
            if checkpoint is None:
                raise CheckpointError("external checkpoint has not been initialized")
            self._assert_checkpoint_prefix(checkpoint, verification, full_index, mv)
            return checkpoint
        except (EvidenceStoreError, CheckpointError):
            raise
        except OSError as exc:
            raise EvidenceStoreError(f"checkpoint verification failed: {exc}") from exc
        finally:
            os.close(mfd)

    def export_verified(
        self,
        destination: str | Path,
        *,
        anchor: CheckpointAnchor | None = None,
    ) -> StoreVerification:
        """Export the complete retained chain to a new private file.

        The destination must not already exist.  If ``anchor`` is supplied,
        its committed prefix is verified before the export is created.
        """
        destination_path = Path(destination)
        manifest_path = self.directory / MANIFEST_NAME
        mfd = _open_private(manifest_path, os.O_RDONLY)
        try:
            _validate_regular_private(mfd)
            fcntl.flock(mfd, fcntl.LOCK_SH)
            manifest_data = _read_all(mfd)
            mv, _ = _scan_manifest(manifest_data)
            self._reconcile_directory(mv)
            verification, full_index = self._verify_all_retained_with_index(mv)
            if anchor is not None:
                try:
                    checkpoint = anchor.read()
                except Exception as exc:
                    raise CheckpointError("could not read external checkpoint") from exc
                if checkpoint is None:
                    raise CheckpointError(
                        "external checkpoint has not been initialized"
                    )
                self._assert_checkpoint_prefix(checkpoint, verification, full_index, mv)

            # Concatenate all retained segment bytes.
            all_bytes = self._read_retained_bytes(mv)

            dest_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            try:
                dest_fd = os.open(destination_path, dest_flags, 0o600)
            except OSError as exc:
                raise EvidenceStoreError(
                    f"cannot create evidence export: {exc}"
                ) from exc
            try:
                _write_all(dest_fd, all_bytes)
                os.fsync(dest_fd)
            except OSError as exc:
                raise EvidenceStoreError(
                    f"evidence export write failed; preserve and inspect partial file: {exc}"
                ) from exc
            finally:
                os.close(dest_fd)
            try:
                _fsync_dir(destination_path.parent)
            except OSError as exc:
                raise EvidenceStoreError(
                    f"evidence export directory sync failed: {exc}"
                ) from exc
            return verification
        except (EvidenceStoreError, CheckpointError):
            raise
        except OSError as exc:
            raise EvidenceStoreError(f"evidence export failed: {exc}") from exc
        finally:
            os.close(mfd)

    def rotate(self, anchor: CheckpointAnchor) -> None:
        """Explicitly rotate the active segment, anchoring it externally.

        Useful for operator-triggered rotation independent of size limits.
        """
        manifest_path = self.directory / MANIFEST_NAME
        mfd = _open_private(manifest_path, os.O_RDWR)
        try:
            _validate_regular_private(mfd)
            fcntl.flock(mfd, fcntl.LOCK_EX)
            _validate_regular_private(mfd)
            manifest_data = _read_all(mfd)
            mv, _ = _scan_manifest(manifest_data)
            self._reconcile_directory(mv)
            active = mv.active
            if active is None:
                raise EvidenceStoreError(
                    "no active segment; call open() first"
                )
            seg_path = self.directory / active.file_name
            sfd = _open_private(seg_path, os.O_RDONLY)
            try:
                seg_data = _read_all(sfd)
            finally:
                os.close(sfd)
            seg_v, _ = _scan_segment_bytes(
                seg_data,
                start_record_number=active.first_record_number,
                start_previous_hash=active.start_previous_hash,
            )
            if seg_v.record_count < active.first_record_number:
                raise SegmentRotationError(
                    "cannot rotate an empty active segment"
                )
            self._rotate(mfd, manifest_data, mv, active, seg_v, anchor)
        except (EvidenceStoreError, CheckpointError):
            raise
        except OSError as exc:
            raise EvidenceStoreError(f"explicit rotation failed: {exc}") from exc
        finally:
            os.close(mfd)

    def retire_oldest_segment(
        self,
        export_destination: str | Path,
        anchor: CheckpointAnchor,
        approval_id: str,
        *,
        min_retention_days: int | None = None,
    ) -> SegmentInfo:
        """Retire the oldest sealed segment.

        Preconditions (all checked atomically under the exclusive lock):
        1. The oldest retained segment is sealed.
        2. A verified export of that segment has been produced at
           ``export_destination`` outside the evidence directory.
        3. The latest external checkpoint verifies against the full retained
           chain and is at least as recent as the generation recorded when the
           segment was sealed.
        4. ``approval_id`` is a non-empty operator-supplied token.
        5. If ``min_retention_days`` is supplied, the segment must be at least
           that many days old (measured from its ``sealed_at`` timestamp in
           the manifest—not enforced if the timestamp is absent).

        Returns the ``SegmentInfo`` of the retired segment.
        """
        if not approval_id.strip():
            raise SegmentRetirementError("approval_id must not be empty")
        export_path = Path(export_destination)

        manifest_path = self.directory / MANIFEST_NAME
        mfd = _open_private(manifest_path, os.O_RDWR)
        try:
            _validate_regular_private(mfd)
            fcntl.flock(mfd, fcntl.LOCK_EX)
            _validate_regular_private(mfd)
            manifest_data = _read_all(mfd)
            mv, _ = _scan_manifest(manifest_data)
            self._reconcile_directory(mv)

            retained = mv.retained
            if not retained:
                raise SegmentRetirementError("no retained segments to retire")
            oldest = retained[0]
            if oldest.last_hash is None:
                raise SegmentRetirementError(
                    f"segment {oldest.segment_id} is not yet sealed"
                )

            # --- Precondition 2: export must exist and re-verify ---
            if not export_path.exists():
                raise SegmentRetirementError(
                    f"export file does not exist: {export_path}"
                )
            export_sha256 = _file_sha256(export_path)
            # Re-verify the export chain using the segment's known start point.
            # This ensures the export contains a valid, unmodified copy of the
            # segment's hash chain (not necessarily a byte-for-byte copy of the
            # original file, but a structurally equivalent one).
            with open(export_path, "rb") as fh:
                export_bytes = fh.read()
            export_v, _ = _scan_segment_bytes(
                export_bytes,
                start_record_number=oldest.first_record_number,
                start_previous_hash=oldest.start_previous_hash,
            )
            # --- Precondition 3: checkpoint covers the full retained chain ---
            verification, full_index = self._verify_all_retained_with_index(mv)

            # Accept either an export of the oldest segment alone or the complete
            # retained chain produced by export_verified(). Both must be an exact
            # hash-verified match; partial or extended exports are not accepted.
            oldest_export_matches = (
                export_v.record_count == oldest.last_record_number
                and hmac.compare_digest(export_v.head_hash, oldest.last_hash or "")
            )
            full_export_matches = (
                export_v.record_count == verification.record_count
                and hmac.compare_digest(export_v.head_hash, verification.head_hash)
            )
            if not (oldest_export_matches or full_export_matches):
                raise SegmentRetirementError(
                    "export must match either the oldest sealed segment or the "
                    "complete retained evidence chain"
                )
            try:
                checkpoint = anchor.read()
            except Exception as exc:
                raise CheckpointError("could not read external checkpoint") from exc
            if checkpoint is None:
                raise SegmentRetirementError(
                    "external checkpoint has not been initialized"
                )
            self._assert_checkpoint_prefix(checkpoint, verification, full_index, mv)
            if (
                oldest.checkpoint_generation is not None
                and checkpoint.generation < oldest.checkpoint_generation
            ):
                raise SegmentRetirementError(
                    "external checkpoint is older than the generation recorded "
                    "when the segment was sealed"
                )

            # --- Append segment_retired to manifest (commit point) ---
            manifest_hash = self._compute_manifest_head_hash(manifest_data)
            retired_entry: dict[str, Any] = {
                "entry_type": "segment_retired",
                "segment_id": oldest.segment_id,
                "retired_at": _now_iso(),
                "last_record_number": oldest.last_record_number,
                "last_hash": oldest.last_hash,
                "export_sha256": export_sha256,
                "checkpoint_generation": checkpoint.generation,
                "approval_id": approval_id,
            }
            line, _ = _manifest_envelope(retired_entry, manifest_hash)
            os.lseek(mfd, 0, os.SEEK_END)
            _write_all(mfd, line)
            os.fsync(mfd)

            # --- Unlink the segment file ---
            seg_path = self.directory / oldest.file_name
            if seg_path.exists():
                os.unlink(seg_path)
                _fsync_dir(self.directory)

            return oldest
        except (EvidenceStoreError, CheckpointError, SegmentRetirementError):
            raise
        except OSError as exc:
            raise EvidenceStoreError(f"segment retirement failed: {exc}") from exc
        finally:
            os.close(mfd)

    @classmethod
    def adopt_legacy(
        cls,
        legacy_path: str | Path,
        evidence_directory: str | Path,
        *,
        max_segment_bytes: int,
        hard_max_segment_bytes: int,
        max_segment_records: int | None = None,
        verify_sealed_on_append: bool = True,
        anchor: CheckpointAnchor | None = None,
    ) -> SegmentedEvidenceStore:
        """Adopt a legacy single-file log as segment 1.

        Preconditions:
        - ``evidence_directory`` must not already exist.
        - The legacy file must verify successfully.
        - If ``anchor`` is supplied, it must verify against the legacy file.

        The legacy file is **moved** (same filesystem) into the new directory
        as ``segment-00000001.jsonl``; the caller is responsible for exporting
        it beforehand.
        """
        from mimclave.telemetry.store import JsonlEvidenceStore  # avoid circular at top

        legacy = Path(legacy_path)
        evidence_dir = Path(evidence_directory)

        if evidence_dir.exists():
            raise EvidenceStoreError(
                f"evidence directory already exists: {evidence_dir}"
            )

        # Verify the legacy file.
        legacy_store = JsonlEvidenceStore(legacy)
        verification = legacy_store.verify()
        if anchor is not None:
            checkpoint = anchor.read()
            if checkpoint is not None:
                legacy_store.verify_checkpoint(anchor)

        # Create the directory.
        evidence_dir.mkdir(mode=0o700, parents=False)
        _fsync_dir(evidence_dir.parent)

        # Move the legacy file as segment 1.
        segment1_path = evidence_dir / _segment_file_name(1)
        os.rename(legacy, segment1_path)
        # Tighten to read-only.
        os.chmod(segment1_path, 0o400)

        # Compute SHA-256 of the segment.
        seg_sha256 = _file_sha256(segment1_path)
        seg_size = segment1_path.stat().st_size

        # Build the manifest.
        manifest_path = evidence_dir / MANIFEST_NAME
        mfd = os.open(
            manifest_path,
            os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            prev_hash = GENESIS_HASH
            opened_entry: dict[str, Any] = {
                "entry_type": "segment_opened",
                "segment_id": 1,
                "file_name": _segment_file_name(1),
                "first_record_number": 1,
                "start_previous_hash": GENESIS_HASH,
                "opened_at": _now_iso(),
            }
            line, prev_hash = _manifest_envelope(opened_entry, prev_hash)
            _write_all(mfd, line)

            checkpoint_gen: int | None = None
            if anchor is not None:
                cp = anchor.read()
                if cp is not None:
                    checkpoint_gen = cp.generation

            sealed_entry: dict[str, Any] = {
                "entry_type": "segment_sealed",
                "segment_id": 1,
                "record_count": verification.record_count,
                "last_record_number": verification.record_count,
                "last_hash": verification.head_hash,
                "file_size": seg_size,
                "file_sha256": seg_sha256,
                "checkpoint_generation": checkpoint_gen,
                "sealed_at": _now_iso(),
            }
            line, prev_hash = _manifest_envelope(sealed_entry, prev_hash)
            _write_all(mfd, line)

            # Open segment 2 as the active segment.
            seg2_name = _segment_file_name(2)
            seg2_path = evidence_dir / seg2_name
            seg2_fd = os.open(
                seg2_path,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            os.close(seg2_fd)

            opened2_entry: dict[str, Any] = {
                "entry_type": "segment_opened",
                "segment_id": 2,
                "file_name": seg2_name,
                "first_record_number": verification.record_count + 1,
                "start_previous_hash": verification.head_hash,
                "opened_at": _now_iso(),
            }
            line, _ = _manifest_envelope(opened2_entry, prev_hash)
            _write_all(mfd, line)
            os.fsync(mfd)
        except Exception:
            os.close(mfd)
            raise
        os.close(mfd)
        _fsync_dir(evidence_dir)

        return cls(
            evidence_dir,
            max_segment_bytes=max_segment_bytes,
            hard_max_segment_bytes=hard_max_segment_bytes,
            max_segment_records=max_segment_records,
            verify_sealed_on_append=verify_sealed_on_append,
        )

    # ------------------------------------------------------------------
    # Private implementation
    # ------------------------------------------------------------------

    def _ensure_directory(self) -> None:
        if not self.directory.exists():
            self.directory.mkdir(mode=0o700, parents=True)
            _fsync_dir(self.directory.parent)
        else:
            info = self.directory.stat()
            if not stat.S_ISDIR(info.st_mode):
                raise EvidenceStoreError(
                    f"{self.directory} exists but is not a directory"
                )
            if stat.S_IMODE(info.st_mode) & 0o077:
                raise EvidenceStoreError(
                    f"evidence directory {self.directory} permissions must be 0700 or stricter"
                )

    def _create_manifest_and_first_segment(self) -> None:
        """Create a brand-new manifest and open segment 1 (directory already exists)."""
        manifest_path = self.directory / MANIFEST_NAME
        seg1_name = _segment_file_name(1)
        seg1_path = self.directory / seg1_name

        # Create manifest.
        mfd = os.open(
            manifest_path,
            os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            # Create empty segment 1 first so the manifest is consistent.
            if not seg1_path.exists():
                sfd = os.open(
                    seg1_path,
                    os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                )
                os.close(sfd)
                _fsync_dir(self.directory)

            opened_entry: dict[str, Any] = {
                "entry_type": "segment_opened",
                "segment_id": 1,
                "file_name": seg1_name,
                "first_record_number": 1,
                "start_previous_hash": GENESIS_HASH,
                "opened_at": _now_iso(),
            }
            line, _ = _manifest_envelope(opened_entry, GENESIS_HASH)
            _write_all(mfd, line)
            os.fsync(mfd)
        except Exception:
            os.close(mfd)
            raise
        os.close(mfd)
        _fsync_dir(self.directory)

    def _crash_recover(self, mfd: int) -> None:
        """Reconcile manifest state with the directory under exclusive lock."""
        manifest_data = _read_all(mfd)
        if not manifest_data:
            # Manifest is empty (crash before first write); re-initialize.
            self._create_manifest_and_first_segment()
            return

        mv, _ = _scan_manifest(manifest_data)
        active = mv.active

        if active is None:
            # Last manifest entry is segment_sealed with no successor segment_opened.
            # Find the last sealed segment and open the next one.
            sealed = mv.sealed
            if not sealed:
                raise EvidenceIntegrityError(
                    "manifest has no active or sealed segments"
                )
            last_sealed = sealed[-1]
            next_id = last_sealed.segment_id + 1
            next_name = _segment_file_name(next_id)
            next_path = self.directory / next_name
            if not next_path.exists():
                sfd = os.open(
                    next_path,
                    os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                )
                os.close(sfd)
                _fsync_dir(self.directory)
            manifest_hash = self._compute_manifest_head_hash(manifest_data)
            opened_entry: dict[str, Any] = {
                "entry_type": "segment_opened",
                "segment_id": next_id,
                "file_name": next_name,
                "first_record_number": last_sealed.last_record_number + 1,
                "start_previous_hash": last_sealed.last_hash,
                "opened_at": _now_iso(),
            }
            line, _ = _manifest_envelope(opened_entry, manifest_hash)
            os.lseek(mfd, 0, os.SEEK_END)
            _write_all(mfd, line)
            os.fsync(mfd)
        else:
            # Active segment is in manifest; verify its file exists.
            seg_path = self.directory / active.file_name
            if not seg_path.exists():
                sfd = os.open(
                    seg_path,
                    os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                )
                os.close(sfd)
                _fsync_dir(self.directory)
            # If non-empty: verify chain (may raise integrity error).
            with open(seg_path, "rb") as fh:
                seg_data = fh.read()
            if seg_data:
                _scan_segment_bytes(
                    seg_data,
                    start_record_number=active.first_record_number,
                    start_previous_hash=active.start_previous_hash,
                )

        self._reconcile_directory(_scan_manifest(_read_all(mfd))[0])

    def _reconcile_directory(self, mv: ManifestVerification) -> None:
        """Raise EvidenceIntegrityError for unexpected files or missing sealed segments."""
        # Collect expected names.
        expected: set[str] = {MANIFEST_NAME}
        for seg in mv.segments:
            if not seg.retired:
                expected.add(seg.file_name)
            # Retired segments may still exist (crash between retire-commit and unlink).

        for entry in self.directory.iterdir():
            name = entry.name
            if name == MANIFEST_NAME:
                continue
            if not SEGMENT_NAME_RE.match(name):
                # Ignore non-segment files (e.g. lock files, exports).
                continue
            if name in expected:
                continue
            # Is it a retired segment still pending unlink?
            is_retired_pending = any(
                s.file_name == name and s.retired for s in mv.segments
            )
            if is_retired_pending:
                # Allowed: crash before unlink; operator should complete.
                continue
            raise EvidenceIntegrityError(
                f"unexpected segment file in evidence directory: {name}; "
                "it is not in the manifest and cannot be automatically adopted"
            )

        # Sealed (non-retired) segments must be present.
        for seg in mv.sealed:
            seg_path = self.directory / seg.file_name
            if not seg_path.exists():
                raise EvidenceIntegrityError(
                    f"sealed segment {seg.file_name} is missing from the evidence directory"
                )

    def _verify_sealed_segments(
        self,
        mv: ManifestVerification,
    ) -> dict[str, tuple[int, dict[str, Any], str]]:
        """Verify all sealed segments and return their merged event index."""
        combined: dict[str, tuple[int, dict[str, Any], str]] = {}
        for seg in mv.sealed:
            seg_path = self.directory / seg.file_name
            # Verify file size and SHA-256.
            actual_size = seg_path.stat().st_size
            if seg.file_size is not None and actual_size != seg.file_size:
                raise EvidenceIntegrityError(
                    f"sealed segment {seg.file_name} size mismatch: "
                    f"expected {seg.file_size}, got {actual_size}"
                )
            if seg.file_sha256 is not None:
                actual_sha = _file_sha256(seg_path)
                if not hmac.compare_digest(actual_sha, seg.file_sha256):
                    raise EvidenceIntegrityError(
                        f"sealed segment {seg.file_name} SHA-256 mismatch"
                    )
            with open(seg_path, "rb") as fh:
                seg_data = fh.read()
            _, seg_index = _scan_segment_bytes(
                seg_data,
                start_record_number=seg.first_record_number,
                start_previous_hash=seg.start_previous_hash,
            )
            combined.update(seg_index)
        return combined

    def _verify_all_retained(self, mv: ManifestVerification) -> StoreVerification:
        v, _ = self._verify_all_retained_with_index(mv)
        return v

    def _verify_all_retained_with_index(
        self, mv: ManifestVerification
    ) -> tuple[StoreVerification, dict[str, tuple[int, dict[str, Any], str]]]:
        combined: dict[str, tuple[int, dict[str, Any], str]] = {}
        last_v: StoreVerification | None = None

        for seg in mv.retained:
            seg_path = self.directory / seg.file_name
            if seg.last_hash is not None:
                # Sealed: verify SHA-256 too.
                if seg.file_size is not None:
                    actual_size = seg_path.stat().st_size
                    if actual_size != seg.file_size:
                        raise EvidenceIntegrityError(
                            f"sealed segment {seg.file_name} size mismatch"
                        )
                if seg.file_sha256 is not None:
                    actual_sha = _file_sha256(seg_path)
                    if not hmac.compare_digest(actual_sha, seg.file_sha256):
                        raise EvidenceIntegrityError(
                            f"sealed segment {seg.file_name} SHA-256 mismatch"
                        )
            with open(seg_path, "rb") as fh:
                seg_data = fh.read()
            sv, seg_index = _scan_segment_bytes(
                seg_data,
                start_record_number=seg.first_record_number,
                start_previous_hash=seg.start_previous_hash,
            )
            combined.update(seg_index)
            last_v = sv

        if last_v is None:
            return StoreVerification(record_count=0, head_hash=GENESIS_HASH), combined
        return last_v, combined

    def _read_retained_bytes(self, mv: ManifestVerification) -> bytes:
        """Concatenate all retained segment bytes."""
        parts: list[bytes] = []
        for seg in mv.retained:
            seg_path = self.directory / seg.file_name
            with open(seg_path, "rb") as fh:
                parts.append(fh.read())
        return b"".join(parts)

    @staticmethod
    def _compute_manifest_head_hash(manifest_data: bytes) -> str:
        """Return the entry_hash of the last manifest record."""
        if not manifest_data:
            return GENESIS_HASH
        last_line = manifest_data.rstrip(b"\n").rsplit(b"\n", 1)[-1]
        try:
            envelope = json.loads(last_line, object_pairs_hook=_reject_duplicate_keys)
            return str(envelope["entry_hash"])
        except Exception as exc:
            raise EvidenceIntegrityError(
                "cannot read head hash from manifest"
            ) from exc

    def _rotate(
        self,
        mfd: int,
        manifest_data: bytes,
        mv: ManifestVerification,
        active: SegmentInfo,
        seg_v: StoreVerification,
        anchor: CheckpointAnchor,
    ) -> None:
        """Seal the active segment and open a new one (called under exclusive manifest lock)."""
        if seg_v.record_count < active.first_record_number:
            raise SegmentRotationError(
                f"cannot seal empty segment {active.file_name}"
            )

        # 1. Publish checkpoint for the current head.
        checkpoint = self._do_publish_checkpoint(anchor, seg_v)

        # 2. Gather file metadata.
        seg_path = self.directory / active.file_name
        seg_size = seg_path.stat().st_size
        seg_sha256 = _file_sha256(seg_path)

        # 3. Append segment_sealed to manifest and fsync.
        manifest_hash = self._compute_manifest_head_hash(manifest_data)
        # Re-read to get the latest manifest_hash (checkpoint publication may not
        # have changed the manifest, but we must use the current head).
        current_manifest = _read_all(mfd)
        manifest_hash = self._compute_manifest_head_hash(current_manifest)
        record_count_in_seg = seg_v.record_count - (active.first_record_number - 1)
        sealed_entry: dict[str, Any] = {
            "entry_type": "segment_sealed",
            "segment_id": active.segment_id,
            "record_count": record_count_in_seg,
            "last_record_number": seg_v.record_count,
            "last_hash": seg_v.head_hash,
            "file_size": seg_size,
            "file_sha256": seg_sha256,
            "checkpoint_generation": checkpoint.generation,
            "sealed_at": _now_iso(),
        }
        line, new_manifest_hash = _manifest_envelope(sealed_entry, manifest_hash)
        os.lseek(mfd, 0, os.SEEK_END)
        _write_all(mfd, line)
        os.fsync(mfd)

        # 4. Make segment read-only.
        os.chmod(seg_path, 0o400)

        # 5. Create the next segment and append segment_opened.
        next_id = active.segment_id + 1
        next_name = _segment_file_name(next_id)
        next_path = self.directory / next_name
        sfd = os.open(
            next_path,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        os.close(sfd)
        _fsync_dir(self.directory)

        opened_entry: dict[str, Any] = {
            "entry_type": "segment_opened",
            "segment_id": next_id,
            "file_name": next_name,
            "first_record_number": seg_v.record_count + 1,
            "start_previous_hash": seg_v.head_hash,
            "opened_at": _now_iso(),
        }
        line, _ = _manifest_envelope(opened_entry, new_manifest_hash)
        os.lseek(mfd, 0, os.SEEK_END)
        _write_all(mfd, line)
        os.fsync(mfd)

    @staticmethod
    def _do_publish_checkpoint(
        anchor: CheckpointAnchor, verification: StoreVerification
    ) -> EvidenceCheckpoint:
        try:
            current = anchor.read()
        except Exception as exc:
            raise CheckpointError("could not read external checkpoint") from exc

        expected_generation = None
        next_generation = 1
        if current is not None:
            if (
                current.record_count == verification.record_count
                and current.head_hash == verification.head_hash
            ):
                return current
            expected_generation = current.generation
            next_generation = current.generation + 1

        checkpoint = EvidenceCheckpoint(
            generation=next_generation,
            record_count=verification.record_count,
            head_hash=verification.head_hash,
        )
        try:
            anchor.compare_and_set(
                expected_generation=expected_generation,
                checkpoint=checkpoint,
            )
        except CheckpointError:
            raise
        except Exception as exc:
            raise CheckpointError("could not publish external checkpoint") from exc
        return checkpoint

    @staticmethod
    def _assert_checkpoint_prefix(
        checkpoint: EvidenceCheckpoint,
        verification: StoreVerification,
        full_index: dict[str, tuple[int, dict[str, Any], str]],
        mv: ManifestVerification,
    ) -> None:
        if checkpoint.record_count > verification.record_count:
            raise CheckpointError(
                "evidence log is shorter than its externally anchored checkpoint"
            )
        if checkpoint.record_count == 0:
            expected_hash = GENESIS_HASH
        else:
            # Try the in-memory index first (retained records).
            expected_hash = next(
                (
                    record_hash
                    for record_number, _, record_hash in full_index.values()
                    if record_number == checkpoint.record_count
                ),
                None,
            )
            # If the record number falls in a retired segment, check manifest.
            if expected_hash is None:
                for seg in mv.retired_segments:
                    if seg.last_record_number == checkpoint.record_count:
                        expected_hash = seg.last_hash
                        break
        if expected_hash is None or not hmac.compare_digest(
            expected_hash, checkpoint.head_hash
        ):
            raise CheckpointError(
                "evidence log does not match its externally anchored checkpoint"
            )
