import os
import stat
from concurrent.futures import ThreadPoolExecutor

import pytest

from mirage.telemetry.events import SessionEventFactory
from mirage.telemetry.store import (
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
