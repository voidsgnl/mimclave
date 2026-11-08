import hashlib
import os
import shutil

import pytest

from mirage.telemetry.checkpoints import (
    CheckpointConflictError,
    CheckpointError,
    EvidenceCheckpoint,
)
from mirage.telemetry.events import SessionEventFactory
from mirage.telemetry.segmented import (
    SegmentedEvidenceStore,
    _rename_directory_noreplace,
)
from mirage.telemetry.store import (
    EvidenceIntegrityError, EvidenceStoreError, JsonlEvidenceStore
)


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



def test_initialization_recovers_manifest_before_segment_creation(tmp_path, monkeypatch):
    directory = tmp_path / "evidence"
    original_open = os.open

    def interrupt_segment_create(path, *args, **kwargs):
        if str(path).endswith("segment-00000001.jsonl"):
            raise RuntimeError("simulated process crash")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr("mirage.telemetry.segmented.os.open", interrupt_segment_create)
    with pytest.raises(RuntimeError, match="simulated"):
        SegmentedEvidenceStore(
            directory,
            max_segment_bytes=500,
            hard_max_segment_bytes=4096,
            anchor=MemoryAnchor(),
        )

    monkeypatch.undo()
    assert (directory / "manifest.jsonl").exists()
    assert not (directory / "segment-00000001.jsonl").exists()

    reopened = SegmentedEvidenceStore(
        directory,
        max_segment_bytes=500,
        hard_max_segment_bytes=4096,
        anchor=MemoryAnchor(),
    )
    assert (directory / "segment-00000001.jsonl").exists()
    assert reopened.verify_all().record_count == 0


def test_initialization_recovers_after_segment_fsync_before_directory_fsync(
    tmp_path, monkeypatch
):
    directory = tmp_path / "evidence"
    original_sync = SegmentedEvidenceStore._fsync_directory
    calls = 0

    def interrupt_second_directory_sync(self):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("simulated process crash")
        return original_sync(self)

    monkeypatch.setattr(
        SegmentedEvidenceStore, "_fsync_directory", interrupt_second_directory_sync
    )
    with pytest.raises(RuntimeError, match="simulated"):
        SegmentedEvidenceStore(
            directory,
            max_segment_bytes=500,
            hard_max_segment_bytes=4096,
            anchor=MemoryAnchor(),
        )

    monkeypatch.undo()
    reopened = SegmentedEvidenceStore(
        directory,
        max_segment_bytes=500,
        hard_max_segment_bytes=4096,
        anchor=MemoryAnchor(),
    )
    assert reopened.verify_all().record_count == 0


def test_append_retry_is_idempotent_after_fsync_before_receipt(
    tmp_path, monkeypatch
):
    store, anchor = make_store(tmp_path, soft=3000, hard=8192)
    event = make_event(1)
    original_fsync = os.fsync

    def interrupt_after_fsync(fd):
        original_fsync(fd)
        raise RuntimeError("simulated process crash after fsync")

    monkeypatch.setattr("mirage.telemetry.segmented.os.fsync", interrupt_after_fsync)
    with pytest.raises(RuntimeError, match="after fsync"):
        store.append(event)

    monkeypatch.undo()
    reopened = SegmentedEvidenceStore(
        store.directory,
        max_segment_bytes=3000,
        hard_max_segment_bytes=8192,
        anchor=anchor,
    )
    receipt = reopened.append(event)
    assert receipt.record_number == 1
    assert reopened.verify_all().record_count == 1


def test_partial_append_fails_closed_after_restart(tmp_path, monkeypatch):
    store, anchor = make_store(tmp_path, soft=3000, hard=8192)

    def interrupt_during_write(fd, data):
        os.write(fd, data[: max(1, len(data) // 2)])
        raise RuntimeError("simulated process crash during write")

    monkeypatch.setattr(store, "_write_all", interrupt_during_write)
    with pytest.raises(RuntimeError, match="during write"):
        store.append(make_event(1))

    monkeypatch.undo()
    with pytest.raises(EvidenceIntegrityError, match="incomplete trailing record"):
        SegmentedEvidenceStore(
            store.directory,
            max_segment_bytes=3000,
            hard_max_segment_bytes=8192,
            anchor=anchor,
        )


def test_migration_failure_before_publish_keeps_source_and_no_destination(
    tmp_path, monkeypatch
):
    anchor = MemoryAnchor()
    source = tmp_path / "legacy.jsonl"
    legacy = JsonlEvidenceStore(source)
    legacy.append(make_event(1))
    original_bytes = source.read_bytes()
    destination = tmp_path / "segmented"

    def interrupt_publish(*args, **kwargs):
        raise RuntimeError("simulated process crash before publish")

    monkeypatch.setattr(
        "mirage.telemetry.segmented._rename_directory_noreplace", interrupt_publish
    )
    with pytest.raises(RuntimeError, match="before publish"):
        SegmentedEvidenceStore.migrate_legacy_log(
            source,
            destination,
            max_segment_bytes=500,
            hard_max_segment_bytes=4096,
            anchor=anchor,
        )

    monkeypatch.undo()
    assert source.read_bytes() == original_bytes
    assert not destination.exists()
    assert not list(tmp_path.glob(".segmented.migration-*"))
    assert anchor.checkpoint.record_count == 1


def test_migration_recovers_complete_destination_if_parent_fsync_fails(
    tmp_path, monkeypatch
):
    anchor = MemoryAnchor()
    source = tmp_path / "legacy.jsonl"
    legacy = JsonlEvidenceStore(source)
    legacy.append(make_event(1))
    original_bytes = source.read_bytes()
    destination = tmp_path / "segmented"
    original_publish = _rename_directory_noreplace
    original_fsync = os.fsync
    published = False

    def track_publish(src, dst):
        nonlocal published
        result = original_publish(src, dst)
        if str(dst) == str(destination):
            published = True
        return result

    def interrupt_parent_sync(fd):
        if published:
            raise RuntimeError("simulated process crash after publish")
        return original_fsync(fd)

    monkeypatch.setattr(
        "mirage.telemetry.segmented._rename_directory_noreplace", track_publish
    )
    monkeypatch.setattr("mirage.telemetry.segmented.os.fsync", interrupt_parent_sync)
    with pytest.raises(RuntimeError, match="after publish"):
        SegmentedEvidenceStore.migrate_legacy_log(
            source,
            destination,
            max_segment_bytes=500,
            hard_max_segment_bytes=4096,
            anchor=anchor,
        )

    monkeypatch.undo()
    assert destination.is_dir()
    assert source.read_bytes() == original_bytes
    reopened = SegmentedEvidenceStore(
        destination,
        max_segment_bytes=500,
        hard_max_segment_bytes=4096,
        anchor=anchor,
    )
    assert reopened.verify_all().record_count == 1



def test_initialization_recovers_after_manifest_fsync_before_segment_creation(
    tmp_path, monkeypatch
):
    directory = tmp_path / "evidence"
    original_fsync = os.fsync

    def interrupt_manifest_fsync(fd):
        target = os.readlink(f"/proc/self/fd/{fd}")
        original_fsync(fd)
        if target.endswith("/manifest.jsonl"):
            raise RuntimeError("simulated process crash after manifest fsync")

    monkeypatch.setattr(
        "mirage.telemetry.segmented.os.fsync", interrupt_manifest_fsync
    )
    with pytest.raises(RuntimeError, match="manifest fsync"):
        SegmentedEvidenceStore(
            directory,
            max_segment_bytes=500,
            hard_max_segment_bytes=4096,
            anchor=MemoryAnchor(),
        )

    monkeypatch.undo()
    reopened = SegmentedEvidenceStore(
        directory,
        max_segment_bytes=500,
        hard_max_segment_bytes=4096,
        anchor=MemoryAnchor(),
    )
    assert (directory / "segment-00000001.jsonl").exists()
    assert reopened.verify_all().record_count == 0


def test_rotation_recovers_after_successor_fsync_before_directory_fsync(
    tmp_path, monkeypatch
):
    store, anchor = make_store(tmp_path)
    store.append(make_event(1))
    original_sync = SegmentedEvidenceStore._fsync_directory
    calls = 0

    def interrupt_second_directory_sync(self):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("simulated process crash after successor fsync")
        return original_sync(self)

    monkeypatch.setattr(
        SegmentedEvidenceStore, "_fsync_directory", interrupt_second_directory_sync
    )
    with pytest.raises(RuntimeError, match="successor fsync"):
        store.rotate()

    monkeypatch.undo()
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



def test_checkpoint_prefix_inside_active_segment_is_verified(tmp_path):
    store, anchor = make_store(tmp_path, soft=3000, hard=8192)
    first = store.append(make_event(1))
    anchor.checkpoint = EvidenceCheckpoint(
        generation=1,
        record_count=first.record_number,
        head_hash=first.record_hash,
    )
    store.append(make_event(2))

    assert store.verify_all().record_count == 2


def test_checkpoint_ahead_of_evidence_is_rejected(tmp_path):
    store, anchor = make_store(tmp_path)
    store.append(make_event(1))
    anchor.checkpoint = EvidenceCheckpoint(
        generation=1,
        record_count=2,
        head_hash="f" * 64,
    )

    with pytest.raises(CheckpointError, match="shorter than its external checkpoint"):
        store.verify_all()


def test_checkpoint_inside_retired_segment_is_rejected(tmp_path):
    store, anchor = make_store(tmp_path, soft=3000, hard=8192)
    store.append(make_event(1))
    store.append(make_event(2))
    store.rotate()
    store.append(make_event(3))
    store.rotate()

    first_segment = store.directory / "segment-00000001.jsonl"
    first_record = first_segment.read_bytes().splitlines()[0]
    first_hash = first_record.rsplit(b'"record_hash":"', 1)[1].split(b'"', 1)[0]
    export = tmp_path / "retired-prefix-export.jsonl"
    shutil.copyfile(first_segment, export)
    export.chmod(0o600)
    store.retire_oldest_segment(export, approval_id="checkpoint-interior-test")

    anchor.checkpoint = EvidenceCheckpoint(
        generation=anchor.checkpoint.generation,
        record_count=1,
        head_hash=first_hash.decode("ascii"),
    )
    with pytest.raises(CheckpointError, match="does not match its external checkpoint"):
        store.verify_all()



def test_legacy_migration_rejects_source_larger_than_hard_limit(tmp_path):
    anchor = MemoryAnchor()
    source = tmp_path / "legacy-large.jsonl"
    legacy = JsonlEvidenceStore(source)
    for index in range(12):
        legacy.append(make_event(index))
    original_bytes = source.read_bytes()
    assert len(original_bytes) > 1024

    with pytest.raises(EvidenceStoreError, match="exceeds the configured hard"):
        SegmentedEvidenceStore.migrate_legacy_log(
            source,
            tmp_path / "segmented",
            max_segment_bytes=512,
            hard_max_segment_bytes=1024,
            anchor=anchor,
        )

    assert source.read_bytes() == original_bytes
    assert anchor.checkpoint is None
    assert not (tmp_path / "segmented").exists()


def test_migration_publication_does_not_overwrite_racing_destination(
    tmp_path, monkeypatch
):
    anchor = MemoryAnchor()
    source = tmp_path / "legacy.jsonl"
    legacy = JsonlEvidenceStore(source)
    legacy.append(make_event(1))
    original_bytes = source.read_bytes()
    destination = tmp_path / "segmented"
    original_publish = _rename_directory_noreplace

    def create_destination_then_publish(staging, target):
        target.mkdir()
        marker = target / "keep.txt"
        marker.write_text("existing destination", encoding="utf-8")
        return original_publish(staging, target)

    monkeypatch.setattr(
        "mirage.telemetry.segmented._rename_directory_noreplace",
        create_destination_then_publish,
    )
    with pytest.raises(EvidenceStoreError, match="destination already exists"):
        SegmentedEvidenceStore.migrate_legacy_log(
            source,
            destination,
            max_segment_bytes=500,
            hard_max_segment_bytes=4096,
            anchor=anchor,
        )

    monkeypatch.undo()
    assert source.read_bytes() == original_bytes
    assert (destination / "keep.txt").read_text(encoding="utf-8") == "existing destination"
    assert not list(tmp_path.glob(".segmented.migration-*"))
