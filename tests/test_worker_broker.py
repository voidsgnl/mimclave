import asyncio
import json
import os
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


async def register_session(
    socket_path: Path,
    session_id: str,
    *,
    protocol: str = "http",
    worker_uid: int | None = None,
    worker_pid: int | None = None,
) -> None:
    """Register trusted client metadata for the current test worker process."""
    reader, writer = await asyncio.open_unix_connection(
        socket_path.with_name(socket_path.name + ".control")
    )
    message = {
        "action": "register",
        "session_id": session_id,
        "protocol": protocol,
        "source_ip": "198.51.100.44",
        "source_port": 45678,
        "worker_uid": os.geteuid() if worker_uid is None else worker_uid,
        "worker_pid": os.getpid() if worker_pid is None else worker_pid,
    }
    writer.write(json.dumps(message).encode("utf-8") + b"\n")
    await writer.drain()
    response = json.loads(await reader.readline())
    writer.close()
    await writer.wait_closed()
    assert response["registered"] is True



async def register_session(socket_path: Path, session_id: str, protocol: str = "http") -> None:
    reader, writer = await asyncio.open_unix_connection(str(socket_path) + ".control")
    payload = {
        "session_id": session_id,
        "protocol": protocol,
        "source_ip": "198.51.100.44",
        "source_port": 49152,
    }
    writer.write(json.dumps(payload).encode("utf-8") + b"\\n")
    await writer.drain()
    response = json.loads(await reader.readline())
    writer.close()
    await writer.wait_closed()
    assert response == {"registered": True}


def test_broker_accepts_valid_worker_event_and_persists_it(tmp_path: Path) -> None:
    async def scenario() -> None:
        socket_path = tmp_path / "broker.sock"
        store = JsonlEvidenceStore(tmp_path / "events.jsonl")
        broker = UnixWorkerEventBroker(socket_path, store, profile_id="web-decoy")
        await broker.start()
        try:
            info = os.lstat(socket_path)
            assert stat.S_ISSOCK(info.st_mode)
            assert stat.S_IMODE(info.st_mode) == 0o600

            event = make_event(str(uuid4()))
            await register_session(socket_path, event.session_id)
            reader, writer = await asyncio.open_unix_connection(socket_path)
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
            assert stored["profile_id"] == "web-decoy"
            assert stored["source_ip"] == "198.51.100.44"
            assert stored["source_port"] == 45678
            assert stored["occurred_at"] != event.timestamp
        finally:
            await broker.close()
        assert not socket_path.exists()

    asyncio.run(scenario())


def test_broker_rejects_wrong_peer_uid(tmp_path: Path) -> None:
    async def scenario() -> None:
        socket_path = tmp_path / "broker.sock"
        broker = UnixWorkerEventBroker(
            socket_path, JsonlEvidenceStore(tmp_path / "events.jsonl"),
            profile_id="web-decoy",
            allowed_uids={os.geteuid() + 1},
        )
        await broker.start()
        try:
            event = make_event(str(uuid4()))
            await register_session(socket_path, event.session_id, worker_uid=os.geteuid() + 1)
            reader, writer = await asyncio.open_unix_connection(socket_path)
            writer.write(encode_worker_event(event))
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
        broker = UnixWorkerEventBroker(socket_path, store, profile_id="web-decoy")
        await broker.start()
        try:
            first_event = make_event(str(uuid4()))
            await register_session(socket_path, first_event.session_id)
            reader, writer = await asyncio.open_unix_connection(socket_path)
            writer.write(encode_worker_event(first_event))
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
        broker = UnixWorkerEventBroker(socket_path, store, profile_id="web-decoy")
        await broker.start()
        try:
            reader, writer = await asyncio.open_unix_connection(socket_path)
            session = str(uuid4())
            await register_session(socket_path, session)
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
            public_dir / "broker.sock",
            JsonlEvidenceStore(tmp_path / "events.jsonl"),
            profile_id="web-decoy",
        )
        with pytest.raises(WorkerBrokerError, match="private 0700"):
            await broker.start()

    asyncio.run(scenario())


def test_broker_refuses_existing_regular_file_socket_path(tmp_path: Path) -> None:
    async def scenario() -> None:
        socket_path = tmp_path / "broker.sock"
        socket_path.write_text("preserve")
        broker = UnixWorkerEventBroker(
            socket_path, JsonlEvidenceStore(tmp_path / "events.jsonl"), profile_id="web-decoy"
        )
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
    broker = UnixWorkerEventBroker(
        Path("/tmp/mirage-test.sock"),
        JsonlEvidenceStore(Path("/tmp/mirage-test-events.jsonl")),
        profile_id="ssh-decoy",
    )
    mapped = broker._to_session_event(event, ("http", "198.51.100.44", 49152, 999999999999.0))
    assert mapped.path == "/terminal/whoami"
    assert mapped.method == "SSH"
    assert mapped.status_code == 200


def test_broker_supports_explicit_worker_group_socket_permissions(tmp_path: Path) -> None:
    async def scenario() -> None:
        group_dir = tmp_path / "worker-group"
        group_dir.mkdir(mode=0o700)
        os.chown(group_dir, os.geteuid(), os.getegid())
        group_dir.chmod(0o710)
        socket_path = group_dir / "broker.sock"
        broker = UnixWorkerEventBroker(
            socket_path,
            JsonlEvidenceStore(tmp_path / "events.jsonl"),
            profile_id="web-decoy",
            allowed_uids={os.geteuid()},
            socket_gid=os.getegid(),
        )
        await broker.start()
        try:
            info = os.lstat(socket_path)
            assert info.st_gid == os.getegid()
            assert stat.S_IMODE(info.st_mode) == 0o660
            event = make_event(str(uuid4()))
            await register_session(socket_path, event.session_id)
            reader, writer = await asyncio.open_unix_connection(socket_path)
            writer.write(encode_worker_event(event))
            await writer.drain()
            assert json.loads(await reader.readline())["accepted"] is True
            writer.close()
            await writer.wait_closed()
        finally:
            await broker.close()

    asyncio.run(scenario())


def test_broker_refuses_to_unlink_an_active_broker_socket(tmp_path: Path) -> None:
    async def scenario() -> None:
        socket_path = tmp_path / "broker.sock"
        first = UnixWorkerEventBroker(
            socket_path, JsonlEvidenceStore(tmp_path / "first.jsonl"), profile_id="web-decoy"
        )
        second = UnixWorkerEventBroker(
            socket_path, JsonlEvidenceStore(tmp_path / "second.jsonl"), profile_id="web-decoy"
        )
        await first.start()
        try:
            with pytest.raises(WorkerBrokerError, match="already listening"):
                await second.start()
            assert stat.S_ISSOCK(os.lstat(socket_path).st_mode)
        finally:
            await first.close()

    asyncio.run(scenario())


def test_broker_uses_its_trusted_profile_not_worker_claim(tmp_path: Path) -> None:
    broker = UnixWorkerEventBroker(
        tmp_path / "unused.sock",
        JsonlEvidenceStore(tmp_path / "events.jsonl"),
        profile_id="trusted-profile",
    )
    event = make_event(str(uuid4()))
    mapped = broker._to_session_event(event, ("ssh", "198.51.100.44", 49152, 999999999999.0))
    assert mapped.profile_id == "trusted-profile"
    assert mapped.source_ip == "198.51.100.44"
    assert mapped.source_port == 49152


def test_broker_requires_normalized_trusted_profile_id(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="profile_id"):
        UnixWorkerEventBroker(
            tmp_path / "unused.sock",
            JsonlEvidenceStore(tmp_path / "events.jsonl"),
            profile_id="../untrusted",
        )


def test_broker_rejects_reuse_of_a_recently_closed_session_id(tmp_path: Path) -> None:
    async def scenario() -> None:
        socket_path = tmp_path / "broker.sock"
        store = JsonlEvidenceStore(tmp_path / "events.jsonl")
        broker = UnixWorkerEventBroker(socket_path, store, profile_id="web-decoy")
        await broker.start()
        session_id = str(uuid4())
        try:
            await register_session(socket_path, session_id)
            reader, writer = await asyncio.open_unix_connection(socket_path)
            await register_session(socket_path, session_id)
            writer.write(encode_worker_event(make_event(session_id)))
            await writer.drain()
            assert json.loads(await reader.readline())["accepted"] is True
            writer.close()
            await writer.wait_closed()
            await reader.readline()

            reader2, writer2 = await asyncio.open_unix_connection(socket_path)
            writer2.write(encode_worker_event(make_event(session_id)))
            await writer2.drain()
            assert json.loads(await reader2.readline())["accepted"] is False
            writer2.close()
            await writer2.wait_closed()
            assert store.verify().record_count == 1
        finally:
            await broker.close()

    asyncio.run(scenario())


def test_broker_shutdown_closes_active_worker_connections(tmp_path: Path) -> None:
    async def scenario() -> None:
        socket_path = tmp_path / "broker.sock"
        broker = UnixWorkerEventBroker(
            socket_path,
            JsonlEvidenceStore(tmp_path / "events.jsonl"),
            profile_id="web-decoy",
            client_idle_timeout=10,
        )
        await broker.start()
        reader, writer = await asyncio.open_unix_connection(socket_path)
        for _ in range(100):
            if broker._active_clients:
                break
            await asyncio.sleep(0.01)
        assert broker._active_clients == 1
        await broker.close()
        assert await asyncio.wait_for(reader.readline(), timeout=1) == b""
        writer.close()
        await writer.wait_closed()
        assert not socket_path.exists()

    asyncio.run(scenario())


def test_broker_rejects_worker_without_supervisor_registration(tmp_path: Path) -> None:
    async def scenario() -> None:
        socket_path = tmp_path / "broker.sock"
        store = JsonlEvidenceStore(tmp_path / "events.jsonl")
        broker = UnixWorkerEventBroker(socket_path, store, profile_id="web-decoy")
        await broker.start()
        try:
            reader, writer = await asyncio.open_unix_connection(socket_path)
            writer.write(encode_worker_event(make_event(str(uuid4()))))
            await writer.drain()
            assert json.loads(await reader.readline())["accepted"] is False
            writer.close()
            await writer.wait_closed()
            assert not (tmp_path / "events.jsonl").exists()
        finally:
            await broker.close()

    asyncio.run(scenario())


def test_broker_binds_worker_pid_to_supervisor_registration(tmp_path: Path) -> None:
    async def scenario() -> None:
        socket_path = tmp_path / "broker.sock"
        store = JsonlEvidenceStore(tmp_path / "events.jsonl")
        broker = UnixWorkerEventBroker(socket_path, store, profile_id="web-decoy")
        await broker.start()
        try:
            event = make_event(str(uuid4()))
            await register_session(socket_path, event.session_id, worker_pid=os.getpid() + 1)
            reader, writer = await asyncio.open_unix_connection(socket_path)
            writer.write(encode_worker_event(event))
            await writer.drain()
            assert json.loads(await reader.readline())["accepted"] is False
            writer.close()
            await writer.wait_closed()
            assert not (tmp_path / "events.jsonl").exists()
        finally:
            await broker.close()

    asyncio.run(scenario())


def test_broker_binds_protocol_to_supervisor_registration(tmp_path: Path) -> None:
    async def scenario() -> None:
        socket_path = tmp_path / "broker.sock"
        store = JsonlEvidenceStore(tmp_path / "events.jsonl")
        broker = UnixWorkerEventBroker(socket_path, store, profile_id="web-decoy")
        await broker.start()
        try:
            event = make_event(str(uuid4()))
            await register_session(socket_path, event.session_id, protocol="ssh")
            reader, writer = await asyncio.open_unix_connection(socket_path)
            writer.write(encode_worker_event(event))
            await writer.drain()
            assert json.loads(await reader.readline())["accepted"] is False
            writer.close()
            await writer.wait_closed()
            assert not (tmp_path / "events.jsonl").exists()
        finally:
            await broker.close()

    asyncio.run(scenario())
