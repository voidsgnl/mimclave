import asyncio
import json
import os
import socket
import stat
from pathlib import Path
from uuid import uuid4

import pytest

from mirage.sandbox.ipc import WorkerEvent, encode_worker_event
from mirage.sandbox.worker_broker import UnixWorkerEventBroker, WorkerBrokerError
from mirage.telemetry.store import JsonlEvidenceStore


def make_event(session_id: str, sequence: int = 1) -> WorkerEvent:
    return WorkerEvent(
        event_id=str(uuid4()),
        session_id=session_id,
        sequence=sequence,
        event_type="http.request",
        timestamp="2026-11-20T18:00:00+00:00",
        profile_id="web-decoy",
        protocol="http",
        source_ip="192.0.2.20",
        source_port=50000,
        method="GET",
        request_path="/login",
        status_code=200,
    )


def test_broker_accepts_valid_worker_event_and_persists_it(tmp_path: Path) -> None:
    async def scenario() -> None:
        socket_path = tmp_path / "broker.sock"
        store = JsonlEvidenceStore(tmp_path / "events.jsonl")
        broker = UnixWorkerEventBroker(socket_path, store)
        await broker.start()
        try:
            info = os.lstat(socket_path)
            assert stat.S_ISSOCK(info.st_mode)
            assert stat.S_IMODE(info.st_mode) == 0o600

            reader, writer = await asyncio.open_unix_connection(socket_path)
            event = make_event(str(uuid4()))
            writer.write(encode_worker_event(event))
            await writer.drain()
            ack = json.loads(await reader.readline())
            assert ack == {
                "accepted": True,
                "event_id": event.event_id,
                "sequence": 1,
            }
            writer.close()
            await writer.wait_closed()

            assert store.verify().record_count == 1
            stored = store.read_events()[0]
            assert stored["path"] == "/login"
            assert stored["event_type"] == "http.request"
        finally:
            await broker.close()
        assert not socket_path.exists()

    asyncio.run(scenario())


def test_broker_rejects_wrong_peer_uid(tmp_path: Path) -> None:
    async def scenario() -> None:
        socket_path = tmp_path / "broker.sock"
        broker = UnixWorkerEventBroker(
            socket_path, JsonlEvidenceStore(tmp_path / "events.jsonl"),
            allowed_uids={os.geteuid() + 1},
        )
        await broker.start()
        try:
            reader, writer = await asyncio.open_unix_connection(socket_path)
            writer.write(encode_worker_event(make_event(str(uuid4()))))
            await writer.drain()
            response = json.loads(await reader.readline())
            assert response["accepted"] is False
            writer.close()
            await writer.wait_closed()
            assert not (tmp_path / "events.jsonl").exists()
        finally:
            await broker.close()

    asyncio.run(scenario())


def test_broker_rejects_multiple_sessions_on_one_connection(tmp_path: Path) -> None:
    async def scenario() -> None:
        socket_path = tmp_path / "broker.sock"
        store = JsonlEvidenceStore(tmp_path / "events.jsonl")
        broker = UnixWorkerEventBroker(socket_path, store)
        await broker.start()
        try:
            reader, writer = await asyncio.open_unix_connection(socket_path)
            writer.write(encode_worker_event(make_event(str(uuid4()))))
            await writer.drain()
            assert json.loads(await reader.readline())["accepted"] is True
            writer.write(encode_worker_event(make_event(str(uuid4()))))
            await writer.drain()
            assert json.loads(await reader.readline())["accepted"] is False
            writer.close()
            await writer.wait_closed()
            assert store.verify().record_count == 1
        finally:
            await broker.close()

    asyncio.run(scenario())


def test_broker_rejects_invalid_sequence_without_persisting(tmp_path: Path) -> None:
    async def scenario() -> None:
        socket_path = tmp_path / "broker.sock"
        store = JsonlEvidenceStore(tmp_path / "events.jsonl")
        broker = UnixWorkerEventBroker(socket_path, store)
        await broker.start()
        try:
            reader, writer = await asyncio.open_unix_connection(socket_path)
            session = str(uuid4())
            writer.write(encode_worker_event(make_event(session, sequence=2)))
            await writer.drain()
            assert json.loads(await reader.readline())["accepted"] is False
            writer.close()
            await writer.wait_closed()
            assert not (tmp_path / "events.jsonl").exists()
        finally:
            await broker.close()

    asyncio.run(scenario())


def test_broker_refuses_insecure_parent_directory(tmp_path: Path) -> None:
    async def scenario() -> None:
        public_dir = tmp_path / "public"
        public_dir.mkdir(mode=0o755)
        public_dir.chmod(0o755)
        broker = UnixWorkerEventBroker(
            public_dir / "broker.sock", JsonlEvidenceStore(tmp_path / "events.jsonl")
        )
        with pytest.raises(WorkerBrokerError, match="private 0700"):
            await broker.start()

    asyncio.run(scenario())


def test_broker_refuses_existing_regular_file_socket_path(tmp_path: Path) -> None:
    async def scenario() -> None:
        socket_path = tmp_path / "broker.sock"
        socket_path.write_text("preserve")
        broker = UnixWorkerEventBroker(socket_path, JsonlEvidenceStore(tmp_path / "events.jsonl"))
        with pytest.raises(WorkerBrokerError, match="non-private or non-socket"):
            await broker.start()
        assert socket_path.read_text() == "preserve"

    asyncio.run(scenario())


def test_ssh_worker_event_maps_only_normalized_command_name() -> None:
    event = WorkerEvent(
        event_id=str(uuid4()),
        session_id=str(uuid4()),
        sequence=1,
        event_type="ssh.command",
        timestamp="2026-11-20T18:00:00+00:00",
        profile_id="ssh-decoy",
        protocol="ssh",
        command_name="whoami",
    )
    mapped = UnixWorkerEventBroker._to_session_event(event)
    assert mapped.path == "/terminal/whoami"
    assert mapped.method == "SSH"
    assert mapped.status_code == 200
