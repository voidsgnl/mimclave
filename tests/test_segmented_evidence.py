import hashlib
import shutil

import pytest

from mirage.telemetry.checkpoints import CheckpointConflictError, EvidenceCheckpoint
from mirage.telemetry.events import SessionEventFactory
from mirage.telemetry.segmented import SegmentedEvidenceStore
from mirage.telemetry.store import EvidenceIntegrityError, EvidenceStoreError


class MemoryAnchor:
    def __init__(self):
        self.checkpoint = None

    def read(self):
        return self.checkpoint

    def compare_and_set(self, *, expected_generation, checkpoint):
        current = None if self.checkpoint is None else self.checkpoint.generation
        if current != expected_generation:
            raise CheckpointConflictError("generation conflict")
        expected = 1 if current is None else current + 1
        if checkpoint.generation != expected:
            raise CheckpointConflictError("generation is not monotonic")
        self.checkpoint = checkpoint


def make_event(index: int = 1):
    factory = SessionEventFactory("test-decoy", session_id=f"session-{index}")
    return factory.record_http_request(
        method="GET",
        target=f"/path/{index}?secret=not-stored",
        status_code=200,
        source_ip="192.0.2.10",
    )


def make_store(tmp_path, *, soft=500, hard=4096):
    anchor = MemoryAnchor()
    store = SegmentedEvidenceStore(
        tmp_path / "evidence",
        max_segment_bytes=soft,
        hard_max_segment_bytes=hard,
        anchor=anchor,
    )
    return store, anchor


def test_append_rotate_and_continue_one_global_chain(tmp_path):
    store, _ = make_store(tmp_path)
    first = make_event(1)
    first_receipt = store.append(first)
    store.rotate()
    second_receipt = store.append(make_event(2))

    result = store.verify_all()
    assert first_receipt.record_number == 1
    assert second_receipt.record_number == 2
    assert result.record_count == 2
    assert (store.directory / "segment-00000001.jsonl").stat().st_mode & 0o777 == 0o400


def test_event_retry_is_idempotent_across_segments(tmp_path):
    store, _ = make_store(tmp_path)
    event = make_event(1)
    receipt = store.append(event)
    store.rotate()

    assert store.append(event) == receipt
    assert store.verify_all().record_count == 1


def test_rotation_requires_external_checkpoint(tmp_path):
    class UnavailableAnchor:
        def read(self):
            raise RuntimeError("offline")

        def compare_and_set(self, *, expected_generation, checkpoint):
            raise RuntimeError("offline")

    store = SegmentedEvidenceStore(
        tmp_path / "evidence",
        max_segment_bytes=500,
        hard_max_segment_bytes=4096,
        anchor=UnavailableAnchor(),
    )
    store.append(make_event())
    with pytest.raises(Exception):
        store.rotate()
    assert store.verify_all().record_count == 1
    assert (store.directory / "segment-00000001.jsonl").exists()


def test_tampered_sealed_segment_is_detected(tmp_path):
    store, _ = make_store(tmp_path)
    store.append(make_event())
    store.rotate()
    path = store.directory / "segment-00000001.jsonl"
    path.chmod(0o600)
    path.write_bytes(path.read_bytes().replace(b'"status_code":200', b'"status_code":201'))
    path.chmod(0o400)

    with pytest.raises(EvidenceIntegrityError):
        store.verify_all()


def test_operator_retirement_requires_matching_export_and_keeps_chain(tmp_path):
    store, _ = make_store(tmp_path)
    store.append(make_event(1))
    store.rotate()
    store.append(make_event(2))

    source = store.directory / "segment-00000001.jsonl"
    export = tmp_path / "archived-segment.jsonl"
    shutil.copyfile(source, export)
    export.chmod(0o600)

    store.retire_oldest_segment(export, approval_id="operator-approval-001")
    assert not source.exists()
    assert hashlib.sha256(export.read_bytes()).hexdigest()
    result = store.verify_all()
    assert result.record_count == 2


def test_retirement_rejects_export_inside_evidence_directory(tmp_path):
    store, _ = make_store(tmp_path)
    store.append(make_event())
    store.rotate()
    export = store.directory / "inside.jsonl"
    export.write_bytes((store.directory / "segment-00000001.jsonl").read_bytes())
    export.chmod(0o600)

    with pytest.raises(EvidenceStoreError, match="outside"):
        store.retire_oldest_segment(export, approval_id="approval")
