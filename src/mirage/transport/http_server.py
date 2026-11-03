"""Loopback-only HTTP transport for the pure MIRAGE HTTP decoy."""

import asyncio
import ssl
from collections.abc import Callable
from ipaddress import ip_address
from typing import Any

from mirage.emulation.http import MAX_REQUEST_BYTES, HttpDecoy, HttpRequest, RequestError
from mirage.telemetry.events import SessionEvent, SessionEventFactory

_BAD_REQUEST = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
_SERVICE_UNAVAILABLE = (
    b"HTTP/1.1 503 Service Unavailable\r\n"
    b"Content-Length: 0\r\nConnection: close\r\n\r\n"
)


class HttpDecoyServer:
    """An opt-in local test server; it cannot bind to a non-loopback address."""

    def __init__(
        self,
        decoy: HttpDecoy,
        *,
        event_sink: Callable[[SessionEvent], None],
        host: str = "127.0.0.1",
        port: int = 0,
        max_connections: int = 32,
        request_timeout: float = 3.0,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        try:
            address = ip_address(host)
        except ValueError as exc:
            raise ValueError("host must be a literal loopback IP address") from exc
        if not address.is_loopback:
            raise ValueError("HTTP decoy transport is restricted to loopback addresses")
        if not 0 <= port <= 65535:
            raise ValueError("port must be between 0 and 65535")
        if max_connections < 1:
            raise ValueError("max_connections must be positive")
        if request_timeout <= 0:
            raise ValueError("request_timeout must be positive")
        if decoy.profile.protocol.value == "https" and ssl_context is None:
            raise ValueError("HTTPS decoys require an explicit server-side SSLContext")
        if decoy.profile.protocol.value == "http" and ssl_context is not None:
            raise ValueError("HTTP decoys must not be configured with a TLS context")
        if ssl_context is not None and ssl_context.protocol != ssl.PROTOCOL_TLS_SERVER:
            raise ValueError("ssl_context must use ssl.PROTOCOL_TLS_SERVER")
        if (
            ssl_context is not None
            and ssl_context.minimum_version < ssl.TLSVersion.TLSv1_2
        ):
            raise ValueError("ssl_context must require TLS 1.2 or newer")
        self.decoy = decoy
        self.event_sink = event_sink
        self.ssl_context = ssl_context
        self.host = str(address)
        self.port = port
        self.max_connections = max_connections
        self.request_timeout = request_timeout
        self._server: asyncio.Server | None = None
        self._writers: set[asyncio.StreamWriter] = set()
        self._tasks: set[asyncio.Task[Any]] = set()
        self._active_connections = 0

    async def start(self) -> None:
        """Start listening on the configured loopback address."""
        if self._server is not None:
            raise RuntimeError("HTTP decoy server is already started")
        self._server = await asyncio.start_server(
            self._handle_client,
            host=self.host,
            port=self.port,
            limit=MAX_REQUEST_BYTES + 1,
            ssl=self.ssl_context,
            ssl_handshake_timeout=(
                self.request_timeout if self.ssl_context is not None else None
            ),
        )

    @property
    def address(self) -> tuple[str, int]:
        """Return the actual bound address, including an OS-assigned port."""
        if self._server is None or not self._server.sockets:
            raise RuntimeError("HTTP decoy server is not started")
        host, port, *_ = self._server.sockets[0].getsockname()
        return str(host), int(port)

    async def close(self) -> None:
        """Stop accepting clients and close all active client connections."""
        if self._server is None:
            return
        server, self._server = self._server, None
        server.close()
        await server.wait_closed()
        writers = tuple(self._writers)
        for writer in writers:
            writer.close()
        tasks = tuple(task for task in self._tasks if task is not asyncio.current_task())
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._tasks.add(task)
        if self._active_connections >= self.max_connections:
            writer.write(_SERVICE_UNAVAILABLE)
            try:
                await asyncio.wait_for(writer.drain(), timeout=self.request_timeout)
            except (TimeoutError, ConnectionError):
                pass
            writer.close()
            if task is not None:
                self._tasks.discard(task)
            return

        self._active_connections += 1
        self._writers.add(writer)
        try:
            async with asyncio.timeout(self.request_timeout):
                raw_request = await reader.readuntil(b"\r\n\r\n")
                if len(raw_request) > MAX_REQUEST_BYTES:
                    raise RequestError("request exceeds maximum size")
                request = HttpRequest.parse(raw_request)
                response = self.decoy.handle(raw_request)
                status_code = int(response.split(b" ", 2)[1].split(b"\r", 1)[0])
                peer = writer.get_extra_info("peername")
                source_ip = str(peer[0]) if isinstance(peer, tuple) and peer else None
                source_port = int(peer[1]) if isinstance(peer, tuple) and len(peer) > 1 else None
                factory = SessionEventFactory(self.decoy.profile.profile_id)
                event = factory.record_http_request(
                    method=request.method,
                    target=request.target,
                    status_code=status_code,
                    source_ip=source_ip,
                    source_port=source_port,
                )
                # If evidence collection fails, do not send an unrecorded decoy response.
                self.event_sink(event)
                writer.write(response)
                await writer.drain()
        except (RequestError, asyncio.LimitOverrunError, asyncio.IncompleteReadError):
            writer.write(_BAD_REQUEST)
            try:
                await asyncio.wait_for(writer.drain(), timeout=self.request_timeout)
            except (TimeoutError, ConnectionError):
                pass
        except (TimeoutError, ConnectionError, OSError):
            pass
        except Exception:
            # A broken telemetry sink must not leak an unrecorded decoy response.
            pass
        finally:
            self._writers.discard(writer)
            self._active_connections -= 1
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=self.request_timeout)
            except (TimeoutError, ConnectionError, OSError):
                pass
            if task is not None:
                self._tasks.discard(task)



class HttpsDecoyServer(HttpDecoyServer):
    """Explicit TLS transport for an HTTPS decoy profile.

    The caller owns certificate provisioning and trust policy. MIRAGE never
    generates, installs, or silently trusts certificates.
    """

    def __init__(
        self,
        decoy: HttpDecoy,
        *,
        event_sink: Callable[[SessionEvent], None],
        ssl_context: ssl.SSLContext,
        host: str = "127.0.0.1",
        port: int = 0,
        max_connections: int = 32,
        request_timeout: float = 3.0,
    ) -> None:
        if decoy.profile.protocol.value != "https":
            raise ValueError("HttpsDecoyServer requires a profile with protocol='https'")
        super().__init__(
            decoy,
            event_sink=event_sink,
            host=host,
            port=port,
            max_connections=max_connections,
            request_timeout=request_timeout,
            ssl_context=ssl_context,
        )
