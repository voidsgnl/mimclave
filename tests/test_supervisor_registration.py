import asyncio
import os
from pathlib import Path
from uuid import uuid4

import pytest

from mirage.sandbox.ipc import WorkerEvent, encode_worker_event
from mirage.sandbox.supervisor import (
    SupervisorRegistrationError,
    register_worker_session,
)
from mirage.sandbox.worker_broker import UnixWorkerEventBroker
from mirage.telemetry.store import JsonlEvidenceStore


def test_supervisor_registration_client_registers_exact_worker_identity(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        socket_path = tmp_path / "worker.sock"
        evidence_path = tmp_path / "events.jsonl"
        store = JsonlEvidenceStore(evidence_path)
        broker = UnixWorkerEventBroker(
            socket_path,
            store,
            profile_id="web-decoy",
            allowed_uids={os.getuid()},
        )
        await broker.start()
        session_id = str(uuid4())
        try:
            await register_worker_session(
                broker.control_socket_path,
                session_id=session_id,
                protocol="http",
                source_ip="192.0.2.44",
                source_port=49152,
                worker_uid=os.getuid(),
                worker_pid=os.getpid(),
            )
            assert session_id in broker._registrations

            event = WorkerEvent(
                event_id=str(uuid4()),
                session_id=session_id,
                sequence=1,
                event_type="http.request",
                timestamp="2026-11-20T19:00:00+00:00",
                profile_id="worker-controlled-value",
                protocol="http",
                source_ip="203.0.113.99",
                source_port=12345,
                method="GET",
                request_path="/login",
                status_code=200,
            )
            reader, writer = await asyncio.open_unix_connection(socket_path)
            writer.write(encode_worker_event(event))
            await writer.drain()
            acknowledgement = await reader.readline()
            assert b'"accepted":true' in acknowledgement
            writer.close()
            await writer.wait_closed()

            report = store.verify()
            assert report.record_count == 1
            evidence = evidence_path.read_text(encoding="utf-8")
            assert "192.0.2.44" in evidence
            assert "203.0.113.99" not in evidence
            assert "trusted-profile" not in evidence
            assert "web-decoy" in evidence
        finally:
            await broker.close()

    asyncio.run(scenario())


@pytest.mark.parametrize("timeout", [0, -1, 30.1, True])
def test_supervisor_registration_client_rejects_invalid_timeout(
    tmp_path: Path, timeout: float
) -> None:
    with pytest.raises(ValueError, match="timeout"):
        asyncio.run(
            register_worker_session(
                tmp_path / "missing.sock",
                session_id=str(uuid4()),
                protocol="http",
                source_ip="192.0.2.44",
                source_port=49152,
                worker_uid=1001,
                worker_pid=1234,
                timeout=timeout,
            )
        )


def test_supervisor_registration_client_fails_closed_when_broker_rejects(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        socket_path = tmp_path / "worker.sock"
        broker = UnixWorkerEventBroker(
            socket_path,
            JsonlEvidenceStore(tmp_path / "events.jsonl"),
            profile_id="web-decoy",
            allowed_uids={os.getuid()},
        )
        await broker.start()
        try:
            with pytest.raises(SupervisorRegistrationError, match="rejected"):
                await register_worker_session(
                    broker.control_socket_path,
                    session_id=str(uuid4()),
                    protocol="http",
                    source_ip="192.0.2.44",
                    source_port=49152,
                    worker_uid=999999,
                    worker_pid=1234,
                )
        finally:
            await broker.close()

    asyncio.run(scenario())
