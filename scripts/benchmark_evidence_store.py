#!/usr/bin/env python3
"""Measure synchronous JSONL evidence append and verification throughput.

Run from the repository root:
    python scripts/benchmark_evidence_store.py --events 100
"""

import argparse
import tempfile
import time
from pathlib import Path

from mirage.telemetry.events import SessionEventFactory
from mirage.telemetry.store import JsonlEvidenceStore


def benchmark(event_count: int) -> None:
    if event_count < 1:
        raise ValueError("event count must be positive")

    with tempfile.TemporaryDirectory(prefix="mirage-evidence-bench-") as directory:
        path = Path(directory) / "events.jsonl"
        store = JsonlEvidenceStore(path)
        factory = SessionEventFactory("benchmark-decoy", session_id="benchmark-session")

        append_started = time.perf_counter()
        for index in range(event_count):
            event = factory.record_http_request(
                method="GET",
                target=f"/benchmark/{index}",
                status_code=200,
                source_ip="192.0.2.10",
                source_port=40000 + (index % 20000),
            )
            store.append(event)
        append_seconds = time.perf_counter() - append_started

        verify_started = time.perf_counter()
        verification = store.verify()
        verify_seconds = time.perf_counter() - verify_started
        file_size = path.stat().st_size

    print(f"events: {verification.record_count}")
    print(f"log size: {file_size} bytes")
    print(f"append total: {append_seconds:.6f} s")
    print(f"append throughput: {event_count / append_seconds:.2f} events/s")
    print(f"full verification: {verify_seconds:.6f} s")
    print(f"verification throughput: {event_count / verify_seconds:.2f} events/s")
    print(f"head hash: {verification.head_hash}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", type=int, default=100)
    args = parser.parse_args()
    benchmark(args.events)


if __name__ == "__main__":
    main()
