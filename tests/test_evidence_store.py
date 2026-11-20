import os
from dataclasses import replace
import stat
from concurrent.futures import ThreadPoolExecutor

import pytest

from mimclave.telemetry.checkpoints import (
    CheckpointConflictError,
    CheckpointError,
    EvidenceCheckpoint,
)
from mimclave.telemetry.events import SessionEventFactory
from mimclave.telemetry.store import (
    EvidenceEventConflictError,
    EvidenceIntegrityError,
    EvidenceStoreError,
    JsonlEvidenceStore,
)


def make_event(index: int = 1):
    factory = SessionEventFactory("test-decoy", session_id=f"session-{index}")
    return factory.record_http_request(
        method="GET",
        target=f"/path/{index}?secret=do-not-store",
        status_code=200,
        source_ip="192.0.2.10",
    )


def test_append_and_verify_hash_chain(tmp_path) -> None:
    store = JsonlEvidenceStore(tmp_path / "events.jsonl")
    first = store.append(make_event(1))
    second = store.append(make_event(2))

    result = store.verify()
    assert first.record_number == 1
    assert second.record_number == 2
    assert result.record_count == 2
    assert result.head_hash == second.record_hash
    assert first.record_hash != second.record_hash


def test_store_uses_private_permissions_and_excludes_query_string(tmp_path) -> None:
    path = tmp_path / "events.jsonl"
    store = JsonlEvidenceStore(path)
    store.append(make_event())
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    content = path.read_text()
    assert "do-not-store" not in content
    assert '"path":"/path/1"' in content


def test_tampered_record_is_detected_and_append_is_refused(tmp_path) -> None:
    path = tmp_path / "events.jsonl"
    store = JsonlEvidenceStore(path)
    store.append(make_event())
    content = path.read_text().replace('"status_code":200', '"status_code":201')
    path.write_text(content)

    with pytest.raises(EvidenceIntegrityError, match="hash mismatch"):
        store.verify()
    with pytest.raises(EvidenceIntegrityError):
        store.append(make_event(2))


def test_incomplete_trailing_record_is_detected(tmp_path) -> None:
    path = tmp_path / "events.jsonl"
    store = JsonlEvidenceStore(path)
    store.append(make_event())
    with path.open("ab") as handle:
        handle.write(b'{"partial":')

    with pytest.raises(EvidenceIntegrityError, match="incomplete trailing"):
        store.verify()


def test_concurrent_appenders_produce_one_valid_chain(tmp_path) -> None:
    store = JsonlEvidenceStore(tmp_path / "events.jsonl")
    with ThreadPoolExecutor(max_workers=8) as pool:
        receipts = list(pool.map(store.append, (make_event(i) for i in range(1, 17))))

    verification = store.verify()
    assert verification.record_count == 16
    assert sorted(receipt.record_number for receipt in receipts) == list(range(1, 17))


def test_symlink_evidence_path_is_rejected(tmp_path) -> None:
    target = tmp_path / "target.jsonl"
    target.write_text("")
    link = tmp_path / "link.jsonl"
    link.symlink_to(target)

    with pytest.raises(EvidenceStoreError):
        JsonlEvidenceStore(link).append(make_event())


def test_existing_group_readable_file_is_rejected(tmp_path) -> None:
    path = tmp_path / "events.jsonl"
    path.write_text("")
    path.chmod(0o640)

    with pytest.raises(EvidenceStoreError, match="permissions"):
        JsonlEvidenceStore(path).append(make_event())


def test_hard_link_evidence_path_is_rejected(tmp_path) -> None:
    path = tmp_path / "events.jsonl"
    alias = tmp_path / "alias.jsonl"
    path.write_text("")
    os.link(path, alias)

    with pytest.raises(EvidenceStoreError, match="hard links"):
        JsonlEvidenceStore(path).append(make_event())



def test_duplicate_json_keys_are_rejected(tmp_path) -> None:
    path = tmp_path / "events.jsonl"
    store = JsonlEvidenceStore(path)
    store.append(make_event())
    line = path.read_text()
    line = line.replace('{"event":', '{"schema_version":1,"event":', 1)
    path.write_text(line)

    with pytest.raises(EvidenceIntegrityError, match="duplicate JSON key"):
        store.verify()



def test_reappending_identical_event_is_idempotent(tmp_path) -> None:
    store = JsonlEvidenceStore(tmp_path / "events.jsonl")
    event = make_event(1)

    first = store.append(event)
    retry = store.append(event)

    assert retry == first
    assert store.verify().record_count == 1


def test_reusing_event_id_with_different_payload_is_rejected(tmp_path) -> None:
    store = JsonlEvidenceStore(tmp_path / "events.jsonl")
    event = make_event(1)
    store.append(event)

    conflicting = replace(event, status_code=201)
    with pytest.raises(EvidenceEventConflictError, match="different payload"):
        store.append(conflicting)

    assert store.verify().record_count == 1



class MemoryCheckpointAnchor:
    """Test double; production anchors must live outside the log trust boundary."""

    def __init__(self) -> None:
        self.checkpoint: EvidenceCheckpoint | None = None

    def read(self) -> EvidenceCheckpoint | None:
        return self.checkpoint

    def compare_and_set(
        self,
        *,
        expected_generation: int | None,
        checkpoint: EvidenceCheckpoint,
    ) -> None:
        current_generation = (
            self.checkpoint.generation if self.checkpoint is not None else None
        )
        if current_generation != expected_generation:
            raise CheckpointConflictError("checkpoint generation changed")
        expected_next = 1 if current_generation is None else current_generation + 1
        if checkpoint.generation != expected_next:
            raise CheckpointConflictError("checkpoint generation is not monotonic")
        self.checkpoint = checkpoint


def test_external_checkpoint_tracks_verified_log_prefix(tmp_path) -> None:
    store = JsonlEvidenceStore(tmp_path / "events.jsonl")
    anchor = MemoryCheckpointAnchor()
    store.append(make_event(1))

    first = store.publish_checkpoint(anchor)
    assert first.generation == 1
    assert first.record_count == 1
    assert store.verify_checkpoint(anchor) == first

    store.append(make_event(2))
    second = store.publish_checkpoint(anchor)
    assert second.generation == 2
    assert second.record_count == 2
    assert store.verify_checkpoint(anchor) == second


def test_external_checkpoint_detects_log_truncation(tmp_path) -> None:
    path = tmp_path / "events.jsonl"
    store = JsonlEvidenceStore(path)
    anchor = MemoryCheckpointAnchor()
    store.append(make_event(1))
    store.append(make_event(2))
    checkpoint = store.publish_checkpoint(anchor)

    lines = path.read_bytes().splitlines(keepends=True)
    path.write_bytes(lines[0])

    with pytest.raises(CheckpointError, match="shorter"):
        store.verify_checkpoint(anchor)
    assert checkpoint.record_count == 2


def test_external_checkpoint_detects_replaced_log_prefix(tmp_path) -> None:
    path = tmp_path / "events.jsonl"
    store = JsonlEvidenceStore(path)
    anchor = MemoryCheckpointAnchor()
    store.append(make_event(1))
    store.publish_checkpoint(anchor)

    replacement = JsonlEvidenceStore(tmp_path / "replacement.jsonl")
    replacement.append(make_event(99))
    path.write_bytes(replacement.path.read_bytes())
    path.chmod(0o600)

    with pytest.raises(CheckpointError, match="does not match"):
        store.verify_checkpoint(anchor)


def test_external_checkpoint_compare_and_set_conflict_is_propagated(tmp_path) -> None:
    store = JsonlEvidenceStore(tmp_path / "events.jsonl")
    store.append(make_event(1))

    class ConflictingAnchor(MemoryCheckpointAnchor):
        def compare_and_set(
            self,
            *,
            expected_generation: int | None,
            checkpoint: EvidenceCheckpoint,
        ) -> None:
            raise CheckpointConflictError("concurrent publisher won")

    with pytest.raises(CheckpointConflictError, match="concurrent publisher"):
        store.publish_checkpoint(ConflictingAnchor())



def test_verified_export_preserves_chain_and_private_permissions(tmp_path) -> None:
    source = tmp_path / "events.jsonl"
    destination = tmp_path / "export.jsonl"
    store = JsonlEvidenceStore(source)
    store.append(make_event(1))
    store.append(make_event(2))
    anchor = MemoryCheckpointAnchor()
    checkpoint = store.publish_checkpoint(anchor)

    result = store.export_verified(destination, anchor=anchor)

    assert result.record_count == 2
    assert result.head_hash == checkpoint.head_hash
    assert destination.read_bytes() == source.read_bytes()
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert JsonlEvidenceStore(destination).verify() == result


def test_verified_export_refuses_to_overwrite_existing_file(tmp_path) -> None:
    source = tmp_path / "events.jsonl"
    destination = tmp_path / "export.jsonl"
    store = JsonlEvidenceStore(source)
    store.append(make_event())
    destination.write_bytes(b"preserve-existing")

    with pytest.raises(EvidenceStoreError, match="cannot create evidence export"):
        store.export_verified(destination)

    assert destination.read_bytes() == b"preserve-existing"


def test_verified_export_requires_matching_external_checkpoint(tmp_path) -> None:
    source = tmp_path / "events.jsonl"
    destination = tmp_path / "export.jsonl"
    store = JsonlEvidenceStore(source)
    store.append(make_event(1))
    anchor = MemoryCheckpointAnchor()
    store.publish_checkpoint(anchor)

    replacement_path = tmp_path / "different.jsonl"
    replacement = JsonlEvidenceStore(replacement_path)
    replacement.append(make_event(99))
    source.write_bytes(replacement_path.read_bytes())

    with pytest.raises(CheckpointError):
        store.export_verified(destination, anchor=anchor)
    assert not destination.exists()
