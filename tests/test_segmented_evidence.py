import hashlib
import shutil

import pytest

from mirage.telemetry.checkpoints import (
    CheckpointConflictError,
    CheckpointError,
    EvidenceCheckpoint,
)
from mirage.telemetry.events import SessionEventFactory
from mirage.telemetry.segmented import SegmentedEvidenceStore
from mirage.telemetry.store import (\n    EvidenceIntegrityError, EvidenceStoreError, JsonlEvidenceStore\n)


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
    with pytest.raises(CheckpointError):
        store.rotate()
    segment = store.directory / "segment-00000001.jsonl"
    assert segment.stat().st_size > 0
    with pytest.raises(CheckpointError):
        store.verify_all()


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



def test_external_checkpoint_mismatch_is_detected(tmp_path):
    store, anchor = make_store(tmp_path)
    store.append(make_event(1))
    store.rotate()
    anchor.checkpoint = EvidenceCheckpoint(
        generation=anchor.checkpoint.generation,
        record_count=anchor.checkpoint.record_count,
        head_hash="f" * 64,
    )

    with pytest.raises(CheckpointError, match="external checkpoint"):
        store.verify_all()


def test_sealed_segments_require_an_external_checkpoint(tmp_path):
    store, anchor = make_store(tmp_path)
    store.append(make_event(1))
    store.rotate()
    anchor.checkpoint = None

    with pytest.raises(CheckpointError, match="without an external checkpoint"):
        store.verify_all()



def test_soft_limit_triggers_automatic_rotation(tmp_path):
    store, anchor = make_store(tmp_path, soft=1, hard=4096)
    receipt = store.append(make_event(1))

    first_segment = store.directory / "segment-00000001.jsonl"
    second_segment = store.directory / "segment-00000002.jsonl"
    assert receipt.record_number == 1
    assert first_segment.stat().st_mode & 0o777 == 0o400
    assert second_segment.exists()
    assert anchor.checkpoint.record_count == 1
    assert store.verify_all().record_count == 1



def test_reopen_recovers_crash_after_seal_before_successor_open(tmp_path):
    store, anchor = make_store(tmp_path)
    store.append(make_event(1))

    with store._locked(exclusive=True) as manifest_fd:
        entries, manifest_head = store._read_manifest(manifest_fd)
        segments = store._reconcile(entries, manifest_fd, manifest_head)
        active = segments[-1]
        path = store.directory / active.file_name
        data = store._read_segment(path, active)
        local_result, _ = store._scan_segment(
            data, active.first_record_number - 1, active.start_previous_hash
        )
        global_result = type(local_result)(
            active.first_record_number - 1 + local_result.record_count,
            local_result.head_hash,
        )
        checkpoint = store._publish_head(global_result)
        store._append_manifest(
            manifest_fd,
            None,
            {
                "type": "segment_sealed",
                "segment_id": active.segment_id,
                "record_count": local_result.record_count,
                "last_record_number": global_result.record_count,
                "last_hash": local_result.head_hash,
                "file_size": len(data),
                "file_sha256": hashlib.sha256(data).hexdigest(),
                "checkpoint_generation": checkpoint.generation,
                "sealed_at": "test",
            },
        )

    reopened = SegmentedEvidenceStore(
        store.directory,
        max_segment_bytes=500,
        hard_max_segment_bytes=4096,
        anchor=anchor,
    )
    assert (store.directory / "segment-00000002.jsonl").exists()
    assert reopened.verify_all().record_count == 1



def test_append_with_sealed_segment_verification_disabled(tmp_path):
    anchor = MemoryAnchor()
    store = SegmentedEvidenceStore(
        tmp_path / "evidence",
        max_segment_bytes=500,
        hard_max_segment_bytes=4096,
        anchor=anchor,
        verify_sealed_on_append=False,
    )
    store.append(make_event(1))
    store.rotate()
    receipt = store.append(make_event(2))

    assert receipt.record_number == 2
    assert store.verify_all().record_count == 2



def test_reopen_recovers_opened_segment_with_missing_file(tmp_path):
    store, anchor = make_store(tmp_path)
    store.append(make_event(1))
    store.rotate()
    active_path = store.directory / "segment-00000002.jsonl"
    active_path.unlink()

    reopened = SegmentedEvidenceStore(
        store.directory,
        max_segment_bytes=500,
        hard_max_segment_bytes=4096,
        anchor=anchor,
    )

    assert active_path.exists()
    assert active_path.stat().st_size == 0
    assert reopened.verify_all().record_count == 1



def test_reopen_after_checkpoint_published_before_seal_manifest(tmp_path, monkeypatch):
    store, anchor = make_store(tmp_path)
    store.append(make_event(1))
    original = store._append_manifest

    def interrupt_before_seal(fd, previous, entry):
        if entry.get("type") == "segment_sealed":
            raise RuntimeError("simulated process crash")
        return original(fd, previous, entry)

    monkeypatch.setattr(store, "_append_manifest", interrupt_before_seal)
    with pytest.raises(RuntimeError, match="simulated"):
        store.rotate()
    assert anchor.checkpoint.record_count == 1

    monkeypatch.setattr(store, "_append_manifest", original)
    reopened = SegmentedEvidenceStore(
        store.directory,
        max_segment_bytes=500,
        hard_max_segment_bytes=4096,
        anchor=anchor,
    )
    assert reopened.verify_all().record_count == 1
    reopened.rotate()
    assert reopened.verify_all().record_count == 1


def test_reopen_after_seal_manifest_before_segment_chmod(tmp_path, monkeypatch):
    store, anchor = make_store(tmp_path)
    store.append(make_event(1))
    original = store._append_manifest

    def interrupt_after_seal(fd, previous, entry):
        result = original(fd, previous, entry)
        if entry.get("type") == "segment_sealed":
            raise RuntimeError("simulated process crash")
        return result

    monkeypatch.setattr(store, "_append_manifest", interrupt_after_seal)
    with pytest.raises(RuntimeError, match="simulated"):
        store.rotate()

    monkeypatch.setattr(store, "_append_manifest", original)
    reopened = SegmentedEvidenceStore(
        store.directory,
        max_segment_bytes=500,
        hard_max_segment_bytes=4096,
        anchor=anchor,
    )
    sealed = store.directory / "segment-00000001.jsonl"
    assert sealed.stat().st_mode & 0o777 == 0o400
    assert (store.directory / "segment-00000002.jsonl").exists()
    assert reopened.verify_all().record_count == 1


def test_reopen_after_seal_fsync_before_successor_manifest(tmp_path, monkeypatch):
    store, anchor = make_store(tmp_path)
    store.append(make_event(1))
    original = store._append_manifest

    def interrupt_before_successor(fd, previous, entry):
        if (
            entry.get("type") == "segment_opened"
            and entry.get("segment_id") == 2
        ):
            raise RuntimeError("simulated process crash")
        return original(fd, previous, entry)

    monkeypatch.setattr(store, "_append_manifest", interrupt_before_successor)
    with pytest.raises(RuntimeError, match="simulated"):
        store.rotate()

    monkeypatch.setattr(store, "_append_manifest", original)
    reopened = SegmentedEvidenceStore(
        store.directory,
        max_segment_bytes=500,
        hard_max_segment_bytes=4096,
        anchor=anchor,
    )
    assert (store.directory / "segment-00000002.jsonl").exists()
    assert reopened.verify_all().record_count == 1


def test_reopen_after_successor_manifest_before_file_creation(tmp_path, monkeypatch):
    store, anchor = make_store(tmp_path)
    store.append(make_event(1))
    original_open = __import__("os").open

    def interrupt_successor_create(path, *args, **kwargs):
        if str(path).endswith("segment-00000002.jsonl"):
            raise RuntimeError("simulated process crash")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr("mirage.telemetry.segmented.os.open", interrupt_successor_create)
    with pytest.raises(RuntimeError, match="simulated"):
        store.rotate()

    monkeypatch.setattr("mirage.telemetry.segmented.os.open", original_open)
    reopened = SegmentedEvidenceStore(
        store.directory,
        max_segment_bytes=500,
        hard_max_segment_bytes=4096,
        anchor=anchor,
    )
    successor = store.directory / "segment-00000002.jsonl"
    assert successor.exists()
    assert successor.stat().st_size == 0
    assert reopened.verify_all().record_count == 1


def test_reopen_after_retirement_manifest_before_unlink(tmp_path, monkeypatch):
    store, anchor = make_store(tmp_path)
    store.append(make_event(1))
    store.rotate()
    source = store.directory / "segment-00000001.jsonl"
    export = tmp_path / "retirement-export.jsonl"
    shutil.copyfile(source, export)
    export.chmod(0o600)
    original_unlink = source.unlink

    def interrupt_unlink(*args, **kwargs):
        raise RuntimeError("simulated process crash")

    monkeypatch.setattr(type(source), "unlink", lambda self, *a, **kw: (
        interrupt_unlink(*a, **kw) if self == source else original_unlink(*a, **kw)
    ))
    with pytest.raises(RuntimeError, match="simulated"):
        store.retire_oldest_segment(export, approval_id="crash-test")

    monkeypatch.undo()
    reopened = SegmentedEvidenceStore(
        store.directory,
        max_segment_bytes=500,
        hard_max_segment_bytes=4096,
        anchor=anchor,
    )
    assert source.exists()
    assert reopened.verify_all().record_count == 1


def test_reopen_after_retirement_unlink_before_directory_fsync(tmp_path, monkeypatch):
    store, anchor = make_store(tmp_path)
    store.append(make_event(1))
    store.rotate()
    source = store.directory / "segment-00000001.jsonl"
    export = tmp_path / "retirement-export.jsonl"
    shutil.copyfile(source, export)
    export.chmod(0o600)

    def interrupt_directory_sync():
        raise RuntimeError("simulated process crash")

    monkeypatch.setattr(store, "_fsync_directory", interrupt_directory_sync)
    with pytest.raises(RuntimeError, match="simulated"):
        store.retire_oldest_segment(export, approval_id="crash-test")

    monkeypatch.undo()
    reopened = SegmentedEvidenceStore(
        store.directory,
        max_segment_bytes=500,
        hard_max_segment_bytes=4096,
        anchor=anchor,
    )
    assert not source.exists()
    assert reopened.verify_all().record_count == 1



def test_manifest_entry_tampering_is_detected(tmp_path):
    store, _ = make_store(tmp_path)
    store.append(make_event(1))
    store.rotate()
    data = store.manifest_path.read_bytes()
    assert b'"segment_id":1' in data
    store.manifest_path.write_bytes(data.replace(b'"segment_id":1', b'"segment_id":9', 1))

    with pytest.raises(EvidenceIntegrityError, match="manifest hash mismatch"):
        store.verify_all()


def test_incomplete_manifest_tail_is_detected(tmp_path):
    store, _ = make_store(tmp_path)
    data = store.manifest_path.read_bytes()
    store.manifest_path.write_bytes(data[:-1])

    with pytest.raises(EvidenceIntegrityError, match="incomplete trailing"):
        store.verify_all()


def test_unmanifested_segment_file_is_detected(tmp_path):
    store, _ = make_store(tmp_path)
    unexpected = store.directory / "segment-00000002.jsonl"
    unexpected.write_bytes(b"")
    unexpected.chmod(0o600)

    with pytest.raises(EvidenceIntegrityError, match="unmanifested"):
        store.verify_all()


def test_missing_sealed_segment_is_detected(tmp_path):
    store, _ = make_store(tmp_path)
    store.append(make_event(1))
    store.rotate()
    (store.directory / "segment-00000001.jsonl").unlink()

    with pytest.raises(EvidenceIntegrityError, match="segment file is missing"):
        store.verify_all()


def test_checkpoint_verifies_across_retired_segment_prefix(tmp_path):
    store, _ = make_store(tmp_path)
    store.append(make_event(1))
    store.rotate()
    store.append(make_event(2))
    store.rotate()

    source = store.directory / "segment-00000001.jsonl"
    export = tmp_path / "retired-prefix-export.jsonl"
    shutil.copyfile(source, export)
    export.chmod(0o600)
    store.retire_oldest_segment(export, approval_id="retired-prefix-checkpoint")

    assert store.verify_all().record_count == 2



def test_legacy_migration_preserves_original_chain_and_source(tmp_path):
    anchor = MemoryAnchor()
    legacy_path = tmp_path / "legacy.jsonl"
    legacy = JsonlEvidenceStore(legacy_path)
    legacy.append(make_event(1))
    legacy.append(make_event(2))
    original_bytes = legacy_path.read_bytes()
    original_verification = legacy.verify()

    migrated = SegmentedEvidenceStore.migrate_legacy_log(
        legacy_path,
        tmp_path / "segmented",
        max_segment_bytes=500,
        hard_max_segment_bytes=4096,
        anchor=anchor,
    )

    first_segment = migrated.directory / "segment-00000001.jsonl"
    assert first_segment.read_bytes() == original_bytes
    assert legacy_path.read_bytes() == original_bytes
    assert migrated.verify_all() == original_verification
    assert anchor.checkpoint.record_count == 2
    assert migrated.append(make_event(3)).record_number == 3
    assert migrated.verify_all().record_count == 3


def test_legacy_migration_rejects_tampered_source_without_destination(tmp_path):
    anchor = MemoryAnchor()
    legacy_path = tmp_path / "legacy.jsonl"
    legacy = JsonlEvidenceStore(legacy_path)
    legacy.append(make_event(1))
    data = legacy_path.read_bytes()
    legacy_path.chmod(0o600)
    legacy_path.write_bytes(data.replace(b'"status_code":200', b'"status_code":201'))

    destination = tmp_path / "segmented"
    with pytest.raises(EvidenceIntegrityError):
        SegmentedEvidenceStore.migrate_legacy_log(
            legacy_path,
            destination,
            max_segment_bytes=500,
            hard_max_segment_bytes=4096,
            anchor=anchor,
        )
    assert not destination.exists()
    assert anchor.checkpoint is None


def test_legacy_migration_rejects_checkpoint_conflict(tmp_path):
    anchor = MemoryAnchor()
    legacy_path = tmp_path / "legacy.jsonl"
    legacy = JsonlEvidenceStore(legacy_path)
    legacy.append(make_event(1))
    anchor.checkpoint = EvidenceCheckpoint(
        generation=1, record_count=1, head_hash="f" * 64
    )

    with pytest.raises(CheckpointError):
        SegmentedEvidenceStore.migrate_legacy_log(
            legacy_path,
            tmp_path / "segmented",
            max_segment_bytes=500,
            hard_max_segment_bytes=4096,
            anchor=anchor,
        )
    assert not (tmp_path / "segmented").exists()
