"""Tests for the segmented evidence store (docs/evidence-segments.md).

Coverage targets from the design's exit criteria:
- Rotation produces segments with correct cross-segment links and global record numbering.
- Rotation refuses to seal when checkpoint publication fails; hard limit fails closed.
- Crash injection at rotation and retirement steps recovers or raises EvidenceIntegrityError.
- Tampering: edited sealed segment, deleted sealed segment, extra segment file,
  edited/truncated manifest, mismatched start_previous_hash, swapped segment order.
- Retirement refuses when segment is not oldest, not sealed, not exported, or not covered.
- Retained range verifies after the oldest segment is retired.
- Checkpoint verification works across a retired boundary.
- Concurrent appenders across a rotation boundary serialize into one valid chain.
- verify_sealed_on_append is exercised in both settings.
"""

import stat
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

import pytest

from mimclave.telemetry.checkpoints import (
    CheckpointConflictError,
    CheckpointError,
    EvidenceCheckpoint,
)
from mimclave.telemetry.events import SessionEventFactory
from mimclave.telemetry.segments import (
    EvidenceIntegrityError,
    EvidenceStoreError,
    SegmentRotationError,
    SegmentRetirementError,
    SegmentedEvidenceStore,
    _segment_file_name,
)
from mimclave.telemetry.store import JsonlEvidenceStore


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


def make_store(
    directory: Path,
    *,
    max_bytes: int = 8 * 1024,
    hard_bytes: int = 16 * 1024,
    max_records: int | None = None,
    verify_sealed: bool = True,
) -> SegmentedEvidenceStore:
    return SegmentedEvidenceStore(
        directory,
        max_segment_bytes=max_bytes,
        hard_max_segment_bytes=hard_bytes,
        max_segment_records=max_records,
        verify_sealed_on_append=verify_sealed,
    )


def make_event(index: int = 1, session: str | None = None):
    factory = SessionEventFactory(
        "test-decoy",
        session_id=session or f"session-{index}",
    )
    return factory.record_http_request(
        method="GET",
        target=f"/path/{index}?secret=x",
        status_code=200,
        source_ip="127.0.0.1",
    )


class MemoryAnchor:
    """In-memory CheckpointAnchor for tests."""

    def __init__(self) -> None:
        self._cp: EvidenceCheckpoint | None = None
        self._lock = threading.Lock()

    def read(self) -> EvidenceCheckpoint | None:
        with self._lock:
            return self._cp

    def compare_and_set(
        self,
        *,
        expected_generation: int | None,
        checkpoint: EvidenceCheckpoint,
    ) -> None:
        with self._lock:
            current_gen = self._cp.generation if self._cp is not None else None
            if current_gen != expected_generation:
                raise CheckpointConflictError("generation conflict")
            expected_next = 1 if current_gen is None else current_gen + 1
            if checkpoint.generation != expected_next:
                raise CheckpointConflictError("generation not monotonic")
            self._cp = checkpoint


class FailingAnchor(MemoryAnchor):
    """Raises CheckpointError on compare_and_set."""

    def compare_and_set(self, *, expected_generation, checkpoint):
        raise CheckpointError("simulated anchor failure")


# ---------------------------------------------------------------------------
# Basic open and append
# ---------------------------------------------------------------------------


def test_open_creates_manifest_and_segment(tmp_path: Path) -> None:
    store = make_store(tmp_path / "evidence")
    store.open()
    ev_dir = tmp_path / "evidence"
    assert (ev_dir / "manifest.jsonl").exists()
    assert (ev_dir / _segment_file_name(1)).exists()


def test_open_is_idempotent(tmp_path: Path) -> None:
    store = make_store(tmp_path / "evidence")
    store.open()
    store.open()  # second open must not raise or corrupt
    store.verify()


def test_append_and_verify_single_segment(tmp_path: Path) -> None:
    store = make_store(tmp_path / "evidence")
    store.open()
    r1 = store.append(make_event(1))
    r2 = store.append(make_event(2))
    assert r1.record_number == 1
    assert r2.record_number == 2
    v = store.verify()
    assert v.record_count == 2
    assert v.head_hash == r2.record_hash


def test_private_permissions(tmp_path: Path) -> None:
    store = make_store(tmp_path / "evidence")
    store.open()
    store.append(make_event())
    ev_dir = tmp_path / "evidence"
    assert stat.S_IMODE(ev_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE((ev_dir / "manifest.jsonl").stat().st_mode) == 0o600
    assert stat.S_IMODE((ev_dir / _segment_file_name(1)).stat().st_mode) == 0o600


def test_query_string_not_stored(tmp_path: Path) -> None:
    store = make_store(tmp_path / "evidence")
    store.open()
    store.append(make_event(1))
    seg_text = (tmp_path / "evidence" / _segment_file_name(1)).read_text()
    assert "secret" not in seg_text


# ---------------------------------------------------------------------------
# Constructor validation
# ---------------------------------------------------------------------------


def test_hard_limit_must_exceed_soft_limit(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="hard_max_segment_bytes must be greater"):
        SegmentedEvidenceStore(
            tmp_path / "ev",
            max_segment_bytes=100,
            hard_max_segment_bytes=100,
        )
    with pytest.raises(ValueError, match="hard_max_segment_bytes must be greater"):
        SegmentedEvidenceStore(
            tmp_path / "ev",
            max_segment_bytes=200,
            hard_max_segment_bytes=100,
        )


# ---------------------------------------------------------------------------
# Rotation
# ---------------------------------------------------------------------------


def test_rotation_on_record_limit_produces_new_segment(tmp_path: Path) -> None:
    anchor = MemoryAnchor()
    store = make_store(tmp_path / "ev", max_bytes=8192, hard_bytes=16384, max_records=2)
    store.open()
    store.append(make_event(1), anchor=anchor)
    store.append(make_event(2), anchor=anchor)
    # This append hits the soft record limit and should rotate.
    store.append(make_event(3), anchor=anchor)

    ev_dir = tmp_path / "ev"
    assert (ev_dir / _segment_file_name(2)).exists()
    # Segment 1 is now read-only.
    assert stat.S_IMODE((ev_dir / _segment_file_name(1)).stat().st_mode) == 0o400

    v = store.verify()
    assert v.record_count == 3


def test_rotation_cross_segment_hash_links_are_correct(tmp_path: Path) -> None:
    """Segment 2's first record must link to segment 1's last hash."""
    import json

    anchor = MemoryAnchor()
    store = make_store(tmp_path / "ev", max_records=1, max_bytes=8192, hard_bytes=16384)
    store.open()
    r1 = store.append(make_event(1), anchor=anchor)
    r2 = store.append(make_event(2), anchor=anchor)

    # Segment 1 last record hash
    seg1_data = (tmp_path / "ev" / _segment_file_name(1)).read_bytes()
    last_line = seg1_data.rstrip(b"\n").rsplit(b"\n", 1)[-1]
    env1 = json.loads(last_line)
    assert env1["record_hash"] == r1.record_hash

    # Segment 2 first record previous_hash must equal segment 1's last hash
    seg2_data = (tmp_path / "ev" / _segment_file_name(2)).read_bytes()
    first_line = seg2_data.split(b"\n")[0]
    env2 = json.loads(first_line)
    assert env2["previous_hash"] == r1.record_hash
    assert r2.record_number == 2


def test_rotation_global_record_numbers_are_continuous(tmp_path: Path) -> None:
    anchor = MemoryAnchor()
    store = make_store(tmp_path / "ev", max_records=2, max_bytes=8192, hard_bytes=16384)
    store.open()
    receipts = [store.append(make_event(i), anchor=anchor) for i in range(1, 7)]
    assert [r.record_number for r in receipts] == list(range(1, 7))
    assert store.verify().record_count == 6


def test_rotation_does_not_seal_when_checkpoint_fails(tmp_path: Path) -> None:
    anchor = FailingAnchor()
    store = make_store(tmp_path / "ev", max_records=1, max_bytes=8192, hard_bytes=16384)
    store.open()
    store.append(make_event(1), anchor=anchor)  # fills segment 1
    # Second append triggers rotation but anchor fails; segment stays open.
    store.append(make_event(2), anchor=anchor)

    ev_dir = tmp_path / "ev"
    # No segment 2 should exist (rotation refused).
    assert not (ev_dir / _segment_file_name(2)).exists()
    # Segment 1 is still writable (not sealed).
    assert stat.S_IMODE((ev_dir / _segment_file_name(1)).stat().st_mode) == 0o600
    v = store.verify()
    assert v.record_count == 2


def test_hard_limit_fails_closed(tmp_path: Path) -> None:
    anchor = FailingAnchor()
    # 500 bytes soft, 600 bytes hard — a few events fill it quickly.
    store = make_store(tmp_path / "ev", max_bytes=500, hard_bytes=600)
    store.open()
    # Fill events until the hard limit is hit.
    with pytest.raises(SegmentRotationError, match="hard size limit"):
        for i in range(100):
            store.append(make_event(i), anchor=anchor)


def test_explicit_rotate(tmp_path: Path) -> None:
    anchor = MemoryAnchor()
    store = make_store(tmp_path / "ev", max_bytes=65536, hard_bytes=131072)
    store.open()
    store.append(make_event(1))
    store.rotate(anchor)
    ev_dir = tmp_path / "ev"
    assert (ev_dir / _segment_file_name(2)).exists()
    assert stat.S_IMODE((ev_dir / _segment_file_name(1)).stat().st_mode) == 0o400
    store.append(make_event(2))
    assert store.verify().record_count == 2


def test_explicit_rotate_empty_segment_raises(tmp_path: Path) -> None:
    anchor = MemoryAnchor()
    store = make_store(tmp_path / "ev", max_bytes=65536, hard_bytes=131072)
    store.open()
    with pytest.raises(SegmentRotationError, match="empty"):
        store.rotate(anchor)


# ---------------------------------------------------------------------------
# Idempotent append
# ---------------------------------------------------------------------------


def test_idempotent_append_returns_original_receipt(tmp_path: Path) -> None:
    store = make_store(tmp_path / "ev")
    store.open()
    event = make_event(1)
    r1 = store.append(event)
    r2 = store.append(event)
    assert r1 == r2
    assert store.verify().record_count == 1


def test_conflicting_event_id_is_rejected(tmp_path: Path) -> None:
    from mimclave.telemetry.store import EvidenceEventConflictError

    store = make_store(tmp_path / "ev")
    store.open()
    event = make_event(1)
    store.append(event)
    conflict = replace(event, status_code=404)
    with pytest.raises(EvidenceEventConflictError, match="different payload"):
        store.append(conflict)


# ---------------------------------------------------------------------------
# Checkpoint
# ---------------------------------------------------------------------------


def test_publish_and_verify_checkpoint(tmp_path: Path) -> None:
    anchor = MemoryAnchor()
    store = make_store(tmp_path / "ev")
    store.open()
    store.append(make_event(1))
    store.append(make_event(2))
    cp = store.publish_checkpoint(anchor)
    assert cp.record_count == 2
    assert store.verify_checkpoint(anchor) == cp


def test_checkpoint_detects_truncation(tmp_path: Path) -> None:
    anchor = MemoryAnchor()
    store = make_store(tmp_path / "ev")
    store.open()
    store.append(make_event(1))
    store.append(make_event(2))
    store.publish_checkpoint(anchor)

    # Truncate the active segment to one record.
    seg_path = tmp_path / "ev" / _segment_file_name(1)
    data = seg_path.read_bytes()
    lines = data.splitlines(keepends=True)
    seg_path.write_bytes(lines[0])

    with pytest.raises(CheckpointError, match="shorter"):
        store.verify_checkpoint(anchor)


def test_checkpoint_detects_replacement(tmp_path: Path) -> None:
    anchor = MemoryAnchor()
    store = make_store(tmp_path / "ev")
    store.open()
    store.append(make_event(1))
    store.publish_checkpoint(anchor)

    # Replace segment 1 with a different chain.
    replacement_dir = tmp_path / "replacement"
    replacement_dir.mkdir(mode=0o700)
    replacement_store = make_store(replacement_dir)
    replacement_store.open()
    replacement_store.append(make_event(99))
    seg_path = tmp_path / "ev" / _segment_file_name(1)
    seg_path.write_bytes((replacement_dir / _segment_file_name(1)).read_bytes())
    seg_path.chmod(0o600)

    with pytest.raises(CheckpointError, match="does not match"):
        store.verify_checkpoint(anchor)


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------


def test_export_verified_concatenates_segments(tmp_path: Path) -> None:
    anchor = MemoryAnchor()
    store = make_store(tmp_path / "ev", max_records=2, max_bytes=8192, hard_bytes=16384)
    store.open()
    store.append(make_event(1), anchor=anchor)
    store.append(make_event(2), anchor=anchor)
    store.append(make_event(3), anchor=anchor)
    store.append(make_event(4), anchor=anchor)
    store.publish_checkpoint(anchor)

    dest = tmp_path / "export.jsonl"
    v = store.export_verified(dest, anchor=anchor)
    assert v.record_count == 4
    assert dest.exists()
    assert stat.S_IMODE(dest.stat().st_mode) == 0o600

    # The exported bytes form a valid evidence chain (readable as a flat JSONL).
    dest_store = JsonlEvidenceStore(dest)
    dest_v = dest_store.verify()
    assert dest_v.record_count == 4


def test_export_refuses_overwrite(tmp_path: Path) -> None:
    store = make_store(tmp_path / "ev")
    store.open()
    store.append(make_event())
    dest = tmp_path / "export.jsonl"
    dest.write_bytes(b"existing")
    with pytest.raises(EvidenceStoreError, match="cannot create evidence export"):
        store.export_verified(dest)
    assert dest.read_bytes() == b"existing"


# ---------------------------------------------------------------------------
# Retirement
# ---------------------------------------------------------------------------


def test_retire_oldest_segment(tmp_path: Path) -> None:
    anchor = MemoryAnchor()
    store = make_store(tmp_path / "ev", max_records=2, max_bytes=8192, hard_bytes=16384)
    store.open()
    store.append(make_event(1), anchor=anchor)
    store.append(make_event(2), anchor=anchor)
    store.append(make_event(3), anchor=anchor)  # triggers rotation
    store.publish_checkpoint(anchor)

    # Export segment 1 specifically (copy the raw sealed segment file).
    import shutil
    export_path = tmp_path / "seg1_export.jsonl"
    shutil.copy2(tmp_path / "ev" / _segment_file_name(1), export_path)
    export_path.chmod(0o600)

    retired = store.retire_oldest_segment(export_path, anchor, "operator-approval-1")
    assert retired.segment_id == 1
    assert not (tmp_path / "ev" / _segment_file_name(1)).exists()

    # Remaining chain still verifies.
    v = store.verify()
    assert v.record_count == 3


def test_retired_segment_no_longer_in_directory(tmp_path: Path) -> None:
    import shutil

    anchor = MemoryAnchor()
    store = make_store(tmp_path / "ev", max_records=1, max_bytes=8192, hard_bytes=16384)
    store.open()
    store.append(make_event(1), anchor=anchor)
    store.append(make_event(2), anchor=anchor)
    store.publish_checkpoint(anchor)
    export_path = tmp_path / "export.jsonl"
    shutil.copy2(tmp_path / "ev" / _segment_file_name(1), export_path)
    export_path.chmod(0o600)
    store.retire_oldest_segment(export_path, anchor, "approval-123")
    ev_dir = tmp_path / "ev"
    assert not (ev_dir / _segment_file_name(1)).exists()
    assert (ev_dir / _segment_file_name(2)).exists()


def test_retirement_requires_sealed_segment(tmp_path: Path) -> None:
    anchor = MemoryAnchor()
    store = make_store(tmp_path / "ev", max_records=10, max_bytes=65536, hard_bytes=131072)
    store.open()
    store.append(make_event(1), anchor=anchor)
    store.publish_checkpoint(anchor)
    export_path = tmp_path / "export.jsonl"
    # Can't retire an active (not-yet-sealed) segment.
    with pytest.raises(SegmentRetirementError, match="not yet sealed"):
        store.retire_oldest_segment(export_path, anchor, "approval-x")


def test_retirement_requires_valid_export(tmp_path: Path) -> None:
    anchor = MemoryAnchor()
    store = make_store(tmp_path / "ev", max_records=1, max_bytes=8192, hard_bytes=16384)
    store.open()
    store.append(make_event(1), anchor=anchor)
    store.append(make_event(2), anchor=anchor)
    store.publish_checkpoint(anchor)

    # Non-existent export
    with pytest.raises(SegmentRetirementError, match="export file does not exist"):
        store.retire_oldest_segment(tmp_path / "missing.jsonl", anchor, "approval")

    # Corrupted export
    export_path = tmp_path / "bad_export.jsonl"
    export_path.write_bytes(b"corrupted\n")
    export_path.chmod(0o600)
    with pytest.raises((EvidenceIntegrityError, SegmentRetirementError)):
        store.retire_oldest_segment(export_path, anchor, "approval")


def test_retirement_requires_matching_checkpoint(tmp_path: Path) -> None:
    import shutil

    anchor = MemoryAnchor()
    store = make_store(tmp_path / "ev", max_records=1, max_bytes=8192, hard_bytes=16384)
    store.open()
    store.append(make_event(1), anchor=anchor)
    store.append(make_event(2), anchor=anchor)
    # Rotation checkpointed through the append anchor. Retirement must reject
    # a different anchor that has no matching checkpoint.
    export_path = tmp_path / "export.jsonl"
    shutil.copy2(tmp_path / "ev" / _segment_file_name(1), export_path)
    export_path.chmod(0o600)
    unpublished_anchor = MemoryAnchor()
    with pytest.raises((SegmentRetirementError, CheckpointError)):
        store.retire_oldest_segment(export_path, unpublished_anchor, "approval")


def test_retirement_requires_nonempty_approval_id(tmp_path: Path) -> None:
    import shutil

    anchor = MemoryAnchor()
    store = make_store(tmp_path / "ev", max_records=1, max_bytes=8192, hard_bytes=16384)
    store.open()
    store.append(make_event(1), anchor=anchor)
    store.append(make_event(2), anchor=anchor)
    store.publish_checkpoint(anchor)
    export_path = tmp_path / "export.jsonl"
    shutil.copy2(tmp_path / "ev" / _segment_file_name(1), export_path)
    export_path.chmod(0o600)
    with pytest.raises(SegmentRetirementError, match="approval_id"):
        store.retire_oldest_segment(export_path, anchor, "   ")


def test_checkpoint_verification_after_retirement(tmp_path: Path) -> None:
    import shutil

    anchor = MemoryAnchor()
    store = make_store(tmp_path / "ev", max_records=1, max_bytes=8192, hard_bytes=16384)
    store.open()
    store.append(make_event(1), anchor=anchor)
    store.append(make_event(2), anchor=anchor)
    # Checkpoint anchored after both records (record_count=2, record 2 is in seg2).
    store.publish_checkpoint(anchor)
    export_path = tmp_path / "export.jsonl"
    shutil.copy2(tmp_path / "ev" / _segment_file_name(1), export_path)
    export_path.chmod(0o600)
    store.retire_oldest_segment(export_path, anchor, "approval-ok")

    # Checkpoint references record 2, which is in retained segment 2.
    # verify_checkpoint must succeed even though segment 1 is retired.
    cp = store.verify_checkpoint(anchor)
    assert cp.record_count == 2


# ---------------------------------------------------------------------------
# Tampering detection
# ---------------------------------------------------------------------------


def test_tampered_sealed_segment_detected_on_verify(tmp_path: Path) -> None:
    anchor = MemoryAnchor()
    store = make_store(tmp_path / "ev", max_records=1, max_bytes=8192, hard_bytes=16384)
    store.open()
    store.append(make_event(1), anchor=anchor)
    store.append(make_event(2), anchor=anchor)

    # Tamper segment 1 (now sealed and 0400).
    seg1 = tmp_path / "ev" / _segment_file_name(1)
    seg1.chmod(0o600)
    content = seg1.read_text().replace('"status_code":200', '"status_code":201')
    seg1.write_text(content)
    seg1.chmod(0o400)

    with pytest.raises(EvidenceIntegrityError, match="mismatch"):
        store.verify()


def test_tampered_sealed_segment_detected_on_append_when_verify_sealed(
    tmp_path: Path,
) -> None:
    anchor = MemoryAnchor()
    store = make_store(
        tmp_path / "ev", max_records=1, max_bytes=8192,
        hard_bytes=16384, verify_sealed=True
    )
    store.open()
    store.append(make_event(1), anchor=anchor)
    store.append(make_event(2), anchor=anchor)

    seg1 = tmp_path / "ev" / _segment_file_name(1)
    seg1.chmod(0o600)
    content = seg1.read_text().replace('"status_code":200', '"status_code":201')
    seg1.write_text(content)
    seg1.chmod(0o400)

    with pytest.raises(EvidenceIntegrityError, match="mismatch"):
        store.append(make_event(3), anchor=anchor)


def test_tampered_sealed_segment_not_detected_on_append_without_verify_sealed(
    tmp_path: Path,
) -> None:
    """With verify_sealed_on_append=False, tampering is not caught on append."""
    anchor = MemoryAnchor()
    store_v = make_store(
        tmp_path / "ev", max_records=1, max_bytes=8192,
        hard_bytes=16384, verify_sealed=True
    )
    store_v.open()
    store_v.append(make_event(1), anchor=anchor)
    store_v.append(make_event(2), anchor=anchor)  # causes rotation

    # Open same directory with verify_sealed_on_append=False.
    store_nv = make_store(
        tmp_path / "ev", max_records=1, max_bytes=8192,
        hard_bytes=16384, verify_sealed=False
    )

    seg1 = tmp_path / "ev" / _segment_file_name(1)
    seg1.chmod(0o600)
    content = seg1.read_text().replace('"status_code":200', '"status_code":201')
    seg1.write_text(content)
    seg1.chmod(0o400)

    # Append does NOT detect the tampering in the sealed segment.
    store_nv.append(make_event(3))

    # But verify() DOES detect it.
    with pytest.raises(EvidenceIntegrityError, match="mismatch"):
        store_nv.verify()


def test_deleted_sealed_segment_detected(tmp_path: Path) -> None:
    anchor = MemoryAnchor()
    store = make_store(tmp_path / "ev", max_records=1, max_bytes=8192, hard_bytes=16384)
    store.open()
    store.append(make_event(1), anchor=anchor)
    store.append(make_event(2), anchor=anchor)

    seg1 = tmp_path / "ev" / _segment_file_name(1)
    seg1.chmod(0o600)
    seg1.unlink()

    with pytest.raises(EvidenceIntegrityError, match="missing"):
        store.verify()


def test_extra_segment_file_detected(tmp_path: Path) -> None:
    store = make_store(tmp_path / "ev")
    store.open()
    store.append(make_event(1))
    # Drop an unexpected segment file into the directory.
    extra = tmp_path / "ev" / _segment_file_name(99)
    extra.write_bytes(b"")
    extra.chmod(0o600)

    with pytest.raises(EvidenceIntegrityError, match="unexpected segment"):
        store.verify()


def test_tampered_manifest_hash_chain_detected(tmp_path: Path) -> None:
    store = make_store(tmp_path / "ev")
    store.open()
    store.append(make_event(1))
    mf = tmp_path / "ev" / "manifest.jsonl"
    text = mf.read_text()
    # Corrupt one byte of the manifest.
    mf.write_text(text.replace('"entry_type"', '"entry_ZZZZ"'))

    with pytest.raises(EvidenceIntegrityError):
        store.verify()


def test_manifest_truncation_detected(tmp_path: Path) -> None:
    anchor = MemoryAnchor()
    store = make_store(tmp_path / "ev", max_records=1, max_bytes=8192, hard_bytes=16384)
    store.open()
    store.append(make_event(1), anchor=anchor)
    store.append(make_event(2), anchor=anchor)
    mf = tmp_path / "ev" / "manifest.jsonl"
    lines = mf.read_bytes().splitlines(keepends=True)
    # Remove the segment_opened or segment_sealed entries.
    mf.write_bytes(lines[0])

    with pytest.raises(EvidenceIntegrityError):
        store.verify()


# ---------------------------------------------------------------------------
# Crash recovery
# ---------------------------------------------------------------------------


def test_crash_recovery_sealed_no_segment_opened(tmp_path: Path) -> None:
    """Simulate a crash after segment_sealed but before segment_opened."""
    import json

    anchor = MemoryAnchor()
    store = make_store(tmp_path / "ev", max_records=1, max_bytes=8192, hard_bytes=16384)
    store.open()
    store.append(make_event(1), anchor=anchor)
    store.append(make_event(2), anchor=anchor)

    # Manually remove the last segment_opened line from the manifest.
    mf = tmp_path / "ev" / "manifest.jsonl"
    lines = mf.read_bytes().splitlines(keepends=True)
    # Find and remove the last segment_opened entry.
    for i in range(len(lines) - 1, -1, -1):
        env = json.loads(lines[i])
        if env["entry"]["entry_type"] == "segment_opened":
            truncated = b"".join(lines[:i])
            mf.write_bytes(truncated)
            break
    # Also remove the segment 2 file so recovery creates it fresh.
    seg2 = tmp_path / "ev" / _segment_file_name(2)
    if seg2.exists():
        seg2.unlink()

    # open() should recover by creating segment 2 and writing segment_opened.
    store.open()
    store.append(make_event(3), anchor=anchor)
    v = store.verify()
    # seg1 has 1 record (event 1); seg2 has event 3 (event 2 was in the
    # deleted seg2 file and is lost).  Record count is 2.
    assert v.record_count == 2


def test_crash_recovery_active_segment_missing_file(tmp_path: Path) -> None:
    """Simulate a crash after segment_opened written but before segment file created."""
    store = make_store(tmp_path / "ev")
    store.open()
    store.append(make_event(1))

    # Remove the active segment file.
    seg1 = tmp_path / "ev" / _segment_file_name(1)
    seg1.unlink()

    # open() should recreate the empty file.
    store.open()
    # Segment is gone — the existing event is lost, but integrity is not violated.
    # A new append should work.
    store.append(make_event(2))


def test_crash_recovery_retired_file_still_present(tmp_path: Path) -> None:
    """Retired segment file still present (crash before unlink) is tolerated."""
    anchor = MemoryAnchor()
    store = make_store(tmp_path / "ev", max_records=1, max_bytes=8192, hard_bytes=16384)
    store.open()
    store.append(make_event(1), anchor=anchor)
    store.append(make_event(2), anchor=anchor)
    store.publish_checkpoint(anchor)
    export_path = tmp_path / "export.jsonl"
    store.export_verified(export_path)
    store.retire_oldest_segment(export_path, anchor, "approval-ok")

    # Simulate crash: re-add the file (pretend unlink didn't finish).
    seg1 = tmp_path / "ev" / _segment_file_name(1)
    # It was already unlinked; write it back.
    seg1.write_bytes((tmp_path / "export.jsonl").read_bytes())
    seg1.chmod(0o600)

    # Store should tolerate this during open/verify.
    store.open()
    # verify() should still pass (the retired file is ignored).
    store.verify()


# ---------------------------------------------------------------------------
# Concurrent appenders
# ---------------------------------------------------------------------------


def test_concurrent_appenders_serialize_into_valid_chain(tmp_path: Path) -> None:
    store = make_store(tmp_path / "ev")
    store.open()

    def _append(i: int):
        return store.append(make_event(i))

    with ThreadPoolExecutor(max_workers=8) as pool:
        receipts = list(pool.map(_append, range(1, 17)))

    v = store.verify()
    assert v.record_count == 16
    assert sorted(r.record_number for r in receipts) == list(range(1, 16 + 1))


def test_concurrent_appenders_across_rotation_boundary(tmp_path: Path) -> None:
    anchor = MemoryAnchor()
    store = make_store(tmp_path / "ev", max_records=4, max_bytes=8192, hard_bytes=16384)
    store.open()

    def _append(i: int):
        return store.append(make_event(i), anchor=anchor)

    with ThreadPoolExecutor(max_workers=4) as pool:
        receipts = list(pool.map(_append, range(1, 13)))

    v = store.verify()
    assert v.record_count == 12
    record_nums = sorted(r.record_number for r in receipts)
    assert record_nums == list(range(1, 13))


# ---------------------------------------------------------------------------
# Legacy adoption
# ---------------------------------------------------------------------------


def test_adopt_legacy_single_file_log(tmp_path: Path) -> None:
    # Create a legacy single-file store with 3 events.
    legacy_path = tmp_path / "legacy.jsonl"
    legacy_store = JsonlEvidenceStore(legacy_path)
    legacy_store.append(make_event(1))
    legacy_store.append(make_event(2))
    legacy_store.append(make_event(3))

    ev_dir = tmp_path / "evidence"
    new_store = SegmentedEvidenceStore.adopt_legacy(
        legacy_path,
        ev_dir,
        max_segment_bytes=65536,
        hard_max_segment_bytes=131072,
    )
    # Legacy file should have been moved.
    assert not legacy_path.exists()
    assert (ev_dir / _segment_file_name(1)).exists()
    # Segment 1 is sealed and read-only.
    assert stat.S_IMODE((ev_dir / _segment_file_name(1)).stat().st_mode) == 0o400
    # Segment 2 is the active segment.
    assert (ev_dir / _segment_file_name(2)).exists()

    # Append a new event and verify the full chain.
    new_store.append(make_event(4))
    v = new_store.verify()
    assert v.record_count == 4


def test_adopt_legacy_refuses_existing_directory(tmp_path: Path) -> None:
    legacy_path = tmp_path / "legacy.jsonl"
    legacy_store = JsonlEvidenceStore(legacy_path)
    legacy_store.append(make_event(1))
    ev_dir = tmp_path / "evidence"
    ev_dir.mkdir()
    with pytest.raises(EvidenceStoreError, match="already exists"):
        SegmentedEvidenceStore.adopt_legacy(
            legacy_path,
            ev_dir,
            max_segment_bytes=65536,
            hard_max_segment_bytes=131072,
        )
