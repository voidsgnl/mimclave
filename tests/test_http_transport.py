import asyncio

import pytest

from mirage.config.models import DecoyProfile, Protocol
from mirage.emulation.http import HttpDecoy
from mirage.telemetry.events import SessionEvent
from mirage.telemetry.store import JsonlEvidenceStore
from mirage.transport.http_server import HttpDecoyServer


def make_decoy() -> HttpDecoy:
    return HttpDecoy(
        DecoyProfile(
            profile_id="local-web",
            name="Local Web",
            protocol=Protocol.HTTP,
            service_name="nginx",
            service_version="1.24",
            hostname="portal.example.test",
        )
    )


def test_transport_only_accepts_loopback_bind_addresses() -> None:
    with pytest.raises(ValueError, match="loopback"):
        HttpDecoyServer(make_decoy(), event_sink=lambda event: None, host="0.0.0.0")
    with pytest.raises(ValueError, match="literal loopback"):
        HttpDecoyServer(make_decoy(), event_sink=lambda event: None, host="localhost")


def test_fragmented_request_is_answered_and_emitted_as_event() -> None:
    async def scenario() -> None:
        events: list[SessionEvent] = []
        server = HttpDecoyServer(make_decoy(), event_sink=events.append)
        await server.start()
        try:
            reader, writer = await asyncio.open_connection(*server.address)
            writer.write(b"GET /?token=private HTTP/1.1\r\n")
            await writer.drain()
            writer.write(b"Host: untrusted.example\r\n\r\n")
            await writer.drain()
            response = await reader.read()
            writer.close()
            await writer.wait_closed()

            assert response.startswith(b"HTTP/1.1 200 OK")
            assert b"portal.example.test" in response
            assert b"untrusted.example" not in response
            assert len(events) == 1
            assert events[0].path == "/"
            assert events[0].source_ip in {"127.0.0.1", "::1"}
            assert events[0].source_port is not None
        finally:
            await server.close()

    asyncio.run(scenario())


def test_malformed_request_gets_bounded_400_response() -> None:
    async def scenario() -> None:
        server = HttpDecoyServer(make_decoy(), event_sink=lambda event: None)
        await server.start()
        try:
            reader, writer = await asyncio.open_connection(*server.address)
            writer.write(b"not a valid request\r\n\r\n")
            await writer.drain()
            response = await reader.read()
            assert response.startswith(b"HTTP/1.1 400 Bad Request")
            writer.close()
            await writer.wait_closed()
        finally:
            await server.close()

    asyncio.run(scenario())


def test_slow_client_times_out_and_does_not_block_shutdown() -> None:
    async def scenario() -> None:
        server = HttpDecoyServer(
            make_decoy(), event_sink=lambda event: None, request_timeout=0.05
        )
        await server.start()
        reader, writer = await asyncio.open_connection(*server.address)
        try:
            assert await asyncio.wait_for(reader.read(), timeout=0.5) == b""
        finally:
            writer.close()
            await writer.wait_closed()
            await server.close()

    asyncio.run(scenario())


def test_connection_limit_rejects_excess_client() -> None:
    async def scenario() -> None:
        server = HttpDecoyServer(
            make_decoy(), event_sink=lambda event: None,
            max_connections=1, request_timeout=1.0,
        )
        await server.start()
        first_reader, first_writer = await asyncio.open_connection(*server.address)
        try:
            second_reader, second_writer = await asyncio.open_connection(*server.address)
            response = await asyncio.wait_for(second_reader.read(), timeout=0.5)
            assert response.startswith(b"HTTP/1.1 503 Service Unavailable")
            second_writer.close()
            await second_writer.wait_closed()
        finally:
            first_writer.close()
            await first_reader.read()
            await first_writer.wait_closed()
            await server.close()

    asyncio.run(scenario())


def test_shutdown_closes_active_clients_and_is_idempotent() -> None:
    async def scenario() -> None:
        server = HttpDecoyServer(make_decoy(), event_sink=lambda event: None)
        await server.start()
        reader, writer = await asyncio.open_connection(*server.address)
        await server.close()
        assert await asyncio.wait_for(reader.read(), timeout=0.5) == b""
        await server.close()
        writer.close()
        await writer.wait_closed()

    asyncio.run(scenario())



def test_oversized_header_is_rejected_without_event() -> None:
    async def scenario() -> None:
        events: list[SessionEvent] = []
        server = HttpDecoyServer(make_decoy(), event_sink=events.append)
        await server.start()
        try:
            reader, writer = await asyncio.open_connection(*server.address)
            writer.write(
                b"GET / HTTP/1.1\r\nHost: "
                + b"a" * 17000
                + b"\r\n\r\n"
            )
            await writer.drain()
            response = await asyncio.wait_for(reader.read(), timeout=1.0)
            assert response.startswith(b"HTTP/1.1 400 Bad Request")
            assert events == []
            writer.close()
            await writer.wait_closed()
        finally:
            await server.close()

    asyncio.run(scenario())


def test_telemetry_sink_failure_suppresses_decoy_response() -> None:
    async def scenario() -> None:
        def broken_sink(event: SessionEvent) -> None:
            raise RuntimeError("evidence store unavailable")

        server = HttpDecoyServer(make_decoy(), event_sink=broken_sink)
        await server.start()
        try:
            reader, writer = await asyncio.open_connection(*server.address)
            writer.write(b"GET / HTTP/1.1\r\nHost: local.test\r\n\r\n")
            await writer.drain()
            assert await asyncio.wait_for(reader.read(), timeout=1.0) == b""
            writer.close()
            await writer.wait_closed()
        finally:
            await server.close()

    asyncio.run(scenario())



def test_transport_uses_durable_evidence_store_before_response(tmp_path) -> None:
    async def scenario() -> None:
        store = JsonlEvidenceStore(tmp_path / "events.jsonl")
        server = HttpDecoyServer(make_decoy(), event_sink=store.append)
        await server.start()
        try:
            reader, writer = await asyncio.open_connection(*server.address)
            writer.write(b"GET / HTTP/1.1\r\nHost: local.test\r\n\r\n")
            await writer.drain()
            response = await reader.read()
            writer.close()
            await writer.wait_closed()

            assert response.startswith(b"HTTP/1.1 200 OK")
            verification = store.verify()
            assert verification.record_count == 1
        finally:
            await server.close()

    asyncio.run(scenario())
