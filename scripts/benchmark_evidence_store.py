#!/usr/bin/env python3
"""Compare legacy JSONL and segmented evidence append/verification throughput.

Run from the repository root:
    python scripts/benchmark_evidence_store.py --events 1000
    python scripts/benchmark_evidence_store.py --events 10000 --segment-bytes 262144

The segmented benchmark uses an in-memory checkpoint double. This measures
local evidence I/O and hashing, not network latency or the durability of a
production independent checkpoint service.
"""

import argparse
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from mimclave.telemetry.checkpoints import (
    CheckpointConflictError,
    EvidenceCheckpoint,
)
from mimclave.telemetry.events import SessionEventFactory
from mimclave.telemetry.segmented import SegmentedEvidenceStore
from mimclave.telemetry.store import JsonlEvidenceStore


class _MemoryAnchor:
    """Benchmark-only checkpoint double; never use as a production anchor."""

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
        current = None if self.checkpoint is None else self.checkpoint.generation
        if current != expected_generation:
            raise CheckpointConflictError("benchmark checkpoint generation conflict")
        expected = 1 if current is None else current + 1
        if checkpoint.generation != expected:
            raise CheckpointConflictError("benchmark checkpoint is not monotonic")
        self.checkpoint = checkpoint


@dataclass(frozen=True)
class _Result:
    name: str
    record_count: int
    append_seconds: float
    verify_seconds: float
    storage_bytes: int
    segment_count: int
    head_hash: str


def _events(count: int):
    factory = SessionEventFactory("benchmark-decoy", session_id="benchmark-session")
    return [
        factory.record_http_request(
            method="GET",
            target=f"/benchmark/{index}",
            status_code=200,
            source_ip="192.0.2.10",
            source_port=40000 + (index % 20000),
        )
        for index in range(count)
    ]


def _benchmark_legacy(directory: Path, events) -> _Result:
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = directory / "events.jsonl"
    store = JsonlEvidenceStore(path)

    append_started = time.perf_counter()
    for event in events:
        store.append(event)
    append_seconds = time.perf_counter() - append_started

    verify_started = time.perf_counter()
    verification = store.verify()
    verify_seconds = time.perf_counter() - verify_started
    return _Result(
        "Legacy JSONL",
        verification.record_count,
        append_seconds,
        verify_seconds,
        path.stat().st_size,
        1,
        verification.head_hash,
    )


def _benchmark_segmented(directory: Path, events, segment_bytes: int) -> _Result:
    anchor = _MemoryAnchor()
    store = SegmentedEvidenceStore(
        directory / "segments",
        max_segment_bytes=segment_bytes,
        hard_max_segment_bytes=segment_bytes * 2,
        anchor=anchor,
    )

    append_started = time.perf_counter()
    for event in events:
        store.append(event)
    append_seconds = time.perf_counter() - append_started

    verify_started = time.perf_counter()
    verification = store.verify_all()
    verify_seconds = time.perf_counter() - verify_started
    files = list(store.directory.glob("segment-*.jsonl"))
    storage_bytes = sum(path.stat().st_size for path in store.directory.iterdir() if path.is_file())
    return _Result(
        "Segmented",
        verification.record_count,
        append_seconds,
        verify_seconds,
        storage_bytes,
        len(files),
        verification.head_hash,
    )


def _print_result(result: _Result) -> None:
    append_rate = result.record_count / result.append_seconds
    verify_rate = result.record_count / result.verify_seconds
    print(f"\n{result.name}")
    print(f"  records: {result.record_count}")
    print(f"  segments: {result.segment_count}")
    print(f"  storage: {result.storage_bytes} bytes")
    print(f"  append: {result.append_seconds:.6f} s ({append_rate:.2f} events/s)")
    print(f"  verify: {result.verify_seconds:.6f} s ({verify_rate:.2f} events/s)")
    print(f"  head hash: {result.head_hash}")


def benchmark(event_count: int, segment_bytes: int) -> None:
    if event_count < 1:
        raise ValueError("event count must be positive")
    if segment_bytes < 1024:
        raise ValueError("segment size must be at least 1024 bytes")

    events = _events(event_count)
    with tempfile.TemporaryDirectory(prefix="mimclave-evidence-bench-") as directory:
        root = Path(directory)
        legacy = _benchmark_legacy(root / "legacy", events)
        segmented = _benchmark_segmented(root, events, segment_bytes)

    _print_result(legacy)
    _print_result(segmented)
    print(
        "\nNote: the in-memory anchor excludes remote checkpoint latency. "
        "Run on target Linux storage with representative event counts and "
        "segment sizes before making performance or sizing decisions."
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", type=int, default=100)
    parser.add_argument("--segment-bytes", type=int, default=256 * 1024)
    args = parser.parse_args()
    benchmark(args.events, args.segment_bytes)


if __name__ == "__main__":
    main()
