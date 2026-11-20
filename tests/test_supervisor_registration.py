import asyncio
from pathlib import Path
from uuid import uuid4

import pytest

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
        store = JsonlEvidenceStore(tmp_path / "events.jsonl")
        broker = UnixWorkerEventBroker(
            socket_path,
            store,
            profile_id="web-decoy",
            allowed_uids={__import__("os").getuid()},
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
                worker_uid=__import__("os").getuid(),
                worker_pid=__import__("os").getpid(),
            )
            assert session_id in broker._registrations
            registration = broker._registrations[session_id]
            assert registration["source_ip"] == "192.0.2.44"
            assert registration["source_port"] == 49152
            assert registration["worker_pid"] == __import__("os").getpid()
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
            allowed_uids={__import__("os").getuid()},
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
