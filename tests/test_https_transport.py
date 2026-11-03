import asyncio
import ssl
import subprocess
from pathlib import Path

import pytest

from mirage.config.models import DecoyProfile, Protocol
from mirage.emulation.http import HttpDecoy
from mirage.telemetry.events import SessionEvent
from mirage.transport.http_server import HttpDecoyServer, HttpsDecoyServer


@pytest.fixture
def tls_material(tmp_path: Path) -> tuple[ssl.SSLContext, ssl.SSLContext]:
    cert = tmp_path / "localhost.crt"
    key = tmp_path / "localhost.key"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", str(key), "-out", str(cert), "-days", "1", "-nodes",
            "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
        ],
        check=True,
        capture_output=True,
    )
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(certfile=cert, keyfile=key)
    client_context = ssl.create_default_context(cafile=cert)
    return server_context, client_context


def make_https_decoy() -> HttpDecoy:
    return HttpDecoy(
        DecoyProfile(
            profile_id="local-https",
            name="Local HTTPS",
            protocol=Protocol.HTTPS,
            service_name="nginx",
            service_version="1.24",
            hostname="portal.example.test",
        )
    )


def test_https_transport_requires_explicit_server_tls_context(
    tls_material: tuple[ssl.SSLContext, ssl.SSLContext],
) -> None:
    server_context, _ = tls_material
    with pytest.raises(ValueError, match="explicit server-side SSLContext"):
        HttpDecoyServer(make_https_decoy(), event_sink=lambda event: None)
    with pytest.raises(ValueError, match="server-side SSLContext"):
        HttpsDecoyServer(
            make_https_decoy(),
            event_sink=lambda event: None,
            ssl_context=ssl.create_default_context(),
        )
    with pytest.raises(ValueError, match="loopback"):
        HttpsDecoyServer(
            make_https_decoy(),
            event_sink=lambda event: None,
            ssl_context=server_context,
            host="0.0.0.0",
        )


def test_https_handshake_and_request_emit_event(
    tls_material: tuple[ssl.SSLContext, ssl.SSLContext],
) -> None:
    async def scenario() -> None:
        server_context, client_context = tls_material
        events: list[SessionEvent] = []
        server = HttpsDecoyServer(
            make_https_decoy(),
            event_sink=events.append,
            ssl_context=server_context,
        )
        await server.start()
        try:
            reader, writer = await asyncio.open_connection(
                *server.address,
                ssl=client_context,
                server_hostname="localhost",
            )
            writer.write(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            await writer.drain()
            response = await reader.read()
            writer.close()
            await writer.wait_closed()

            assert response.startswith(b"HTTP/1.1 200 OK")
            assert b"portal.example.test" in response
            assert len(events) == 1
            assert events[0].profile_id == "local-https"
            assert events[0].path == "/"
        finally:
            await server.close()

    asyncio.run(scenario())


def test_https_client_rejects_untrusted_certificate(
    tls_material: tuple[ssl.SSLContext, ssl.SSLContext],
) -> None:
    async def scenario() -> None:
        server_context, _ = tls_material
        server = HttpsDecoyServer(
            make_https_decoy(),
            event_sink=lambda event: None,
            ssl_context=server_context,
        )
        await server.start()
        try:
            with pytest.raises((ssl.SSLCertVerificationError, OSError)):
                await asyncio.open_connection(
                    *server.address,
                    ssl=ssl.create_default_context(),
                    server_hostname="localhost",
                )
        finally:
            await server.close()

    asyncio.run(scenario())
