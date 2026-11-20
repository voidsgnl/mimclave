"""Loopback-only SSH transport for the in-memory virtual terminal.

The optional AsyncSSH dependency handles SSH protocol and cryptography. This
adapter never invokes a host shell, reads host files, or enables forwarding.
"""

import asyncio
import re
import stat
from collections.abc import Callable
from ipaddress import ip_address
from pathlib import Path

try:
    import asyncssh
except ImportError:  # pragma: no cover - exercised when the optional extra is absent
    asyncssh = None  # type: ignore[assignment]

from mirage.emulation.terminal import MAX_COMMAND_LENGTH, VirtualTerminal
from mirage.telemetry.events import SessionEvent, SessionEventFactory

MAX_COMMANDS_PER_SESSION = 100
COMMAND_IDLE_TIMEOUT = 30.0
PROMPT = "{username}@{hostname}:{cwd}$ "

_SSH_BASE = asyncssh.SSHServer if asyncssh is not None else object


class _NoAuthSSHServer(_SSH_BASE):  # type: ignore[misc,valid-type]
    """Accept a connection without asking for credentials; deny all forwarding."""

    def __init__(self, owner: "SSHDecoyServer") -> None:
        self._owner = owner
        self._connection = None

    def connection_made(self, connection: object) -> None:
        self._connection = connection
        if len(self._owner._connections) >= self._owner.max_connections:
            connection.close()  # type: ignore[attr-defined]
            return
        self._owner._connections.add(connection)

    def connection_lost(self, exc: Exception | None) -> None:
        del exc
        if self._connection is not None:
            self._owner._connections.discard(self._connection)

    def begin_auth(self, username: str) -> bool:
        del username
        return False

    def connection_requested(self, *args: object) -> bool:
        del args
        return False

    def server_requested(self, *args: object) -> bool:
        del args
        return False

    def unix_connection_requested(self, *args: object) -> bool:
        del args
        return False

    def unix_server_requested(self, *args: object) -> bool:
        del args
        return False


class SSHDecoyServer:
    """A bounded SSH front-end to per-connection in-memory terminal instances."""

    def __init__(
        self,
        *,
        event_sink: Callable[[SessionEvent], object],
        host_key: str | Path,
        profile_id: str = "local-ssh",
        host: str = "127.0.0.1",
        port: int = 2222,
        max_sessions: int = 8,
        max_connections: int = 16,
        idle_timeout: float = COMMAND_IDLE_TIMEOUT,
    ) -> None:
        if asyncssh is None:
            raise RuntimeError(
                "SSH support requires the optional dependency; install mirage-deception[ssh]"
            )
        try:
            address = ip_address(host)
        except ValueError as exc:
            raise ValueError("SSH host must be a literal loopback IP address") from exc
        if not address.is_loopback:
            raise ValueError("SSH decoy transport is restricted to loopback addresses")
        if not 0 <= port <= 65535:
            raise ValueError("port must be between 0 and 65535")
        if max_sessions < 1:
            raise ValueError("max_sessions must be positive")
        if max_connections < 1:
            raise ValueError("max_connections must be positive")
        if idle_timeout <= 0:
            raise ValueError("idle_timeout must be positive")
        if not profile_id.strip():
            raise ValueError("profile_id must not be empty")

        key_path = Path(host_key)
        try:
            key_info = key_path.lstat()
        except OSError as exc:
            raise ValueError(f"cannot inspect SSH host key: {exc}") from exc
        if not stat.S_ISREG(key_info.st_mode) or key_info.st_nlink != 1:
            raise ValueError("SSH host key must be a regular file without hard links")
        if stat.S_IMODE(key_info.st_mode) & 0o077:
            raise ValueError("SSH host key permissions must be 0600 or stricter")

        self.event_sink = event_sink
        self.host_key = key_path
        self.profile_id = profile_id
        self.host = str(address)
        self.port = port
        self.max_sessions = max_sessions
        self.max_connections = max_connections
        self.idle_timeout = idle_timeout
        self._server: object | None = None
        self._active_sessions = 0
        self._connections: set[object] = set()

    @property
    def address(self) -> tuple[str, int]:
        """Return the actual bound address."""
        if self._server is None:
            raise RuntimeError("SSH decoy server is not started")
        sockets = self._server.sockets  # type: ignore[attr-defined]
        if not sockets:
            raise RuntimeError("SSH decoy server has no listening socket")
        host, port, *_ = sockets[0].getsockname()
        return str(host), int(port)

    async def start(self) -> None:
        """Start the SSH listener on a literal loopback address only."""
        if self._server is not None:
            raise RuntimeError("SSH decoy server is already started")
        assert asyncssh is not None
        self._server = await asyncssh.create_server(
            lambda: _NoAuthSSHServer(self),
            host=self.host,
            port=self.port,
            server_host_keys=[str(self.host_key)],
            process_factory=self._handle_process,
            allow_pty=True,
            line_editor=False,
            agent_forwarding=False,
            x11_forwarding=False,
            login_timeout=10,
            backlog=self.max_connections,
            window=4096,
            max_pktsize=1024,
            encoding="utf-8",
        )

    async def close(self) -> None:
        """Stop accepting SSH clients and close the listener."""
        if self._server is None:
            return
        server, self._server = self._server, None
        server.close()  # type: ignore[attr-defined]
        await server.wait_closed()  # type: ignore[attr-defined]
        connections = tuple(self._connections)
        for connection in connections:
            connection.close()  # type: ignore[attr-defined]
        if connections:
            await asyncio.gather(
                *(connection.wait_closed() for connection in connections),  # type: ignore[attr-defined]
                return_exceptions=True,
            )

    async def _read_command(self, process: object) -> str | None:
        """Read one bounded command with an absolute line deadline."""
        reader = process.stdin  # type: ignore[attr-defined]
        chars: list[str] = []
        try:
            async with asyncio.timeout(self.idle_timeout):
                while len(chars) <= MAX_COMMAND_LENGTH:
                    char = await reader.read(1)
                    if not char:
                        return None if not chars else "".join(chars)
                    if char in ("\\n", "\\r"):
                        return "".join(chars)
                    chars.append(char)
        except TimeoutError:
            return None
        raise ValueError("command exceeds the maximum length")

    @staticmethod
    def _command_identifier(command: str) -> str:
        parts = command.strip().split(maxsplit=1)
        if not parts:
            return "empty"
        candidate = parts[0].lower()
        return candidate if re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", candidate) else "other"

    @staticmethod
    def _peer(process: object) -> tuple[str | None, int | None]:
        peer = process.get_extra_info("peername")  # type: ignore[attr-defined]
        if not isinstance(peer, tuple) or not peer:
            return None, None
        source_ip = str(peer[0])
        source_port = int(peer[1]) if len(peer) > 1 else None
        return source_ip, source_port

    async def _record_and_execute(
        self,
        process: object,
        terminal: VirtualTerminal,
        factory: SessionEventFactory,
        command: str,
    ) -> str:
        source_ip, source_port = self._peer(process)
        event = factory.record_terminal_command(
            command_name=self._command_identifier(command),
            source_ip=source_ip,
            source_port=source_port,
        )
        # Evidence must be durable before any simulated command output is sent.
        self.event_sink(event)
        return terminal.execute(command)

    async def _handle_process(self, process: object) -> None:
        """Serve one SSH shell or exec channel with isolated virtual state."""
        if self._active_sessions >= self.max_sessions:
            process.stderr.write("MIRAGE: session capacity reached.\\r\\n")  # type: ignore[attr-defined]
            process.exit(1)  # type: ignore[attr-defined]
            return

        self._active_sessions += 1
        try:
            if process.subsystem:  # type: ignore[attr-defined]
                process.stderr.write("MIRAGE: subsystem unavailable.\\r\\n")  # type: ignore[attr-defined]
                process.exit(1)  # type: ignore[attr-defined]
                return

            terminal = VirtualTerminal()
            factory = SessionEventFactory(self.profile_id)
            if process.command is not None:  # type: ignore[attr-defined]
                command = process.command  # type: ignore[attr-defined]
                if len(command) > MAX_COMMAND_LENGTH:
                    process.stderr.write("mirage: input too long\\r\\n")  # type: ignore[attr-defined]
                    process.exit(2)  # type: ignore[attr-defined]
                    return
                output = await self._record_and_execute(process, terminal, factory, command)
                if output:
                    process.stdout.write(output + "\\r\\n")  # type: ignore[attr-defined]
                    await process.stdout.drain()  # type: ignore[attr-defined]
                process.exit(0)  # type: ignore[attr-defined]
                return

            process.stdout.write(
                "MIRAGE virtual terminal — simulated data only; no host commands execute.\\r\\n"
            )  # type: ignore[attr-defined]
            commands_handled = 0
            while True:
                process.stdout.write(  # type: ignore[attr-defined]
                    PROMPT.format(
                        username=terminal.username,
                        hostname=terminal.hostname,
                        cwd=terminal.cwd,
                    )
                )
                await process.stdout.drain()  # type: ignore[attr-defined]
                try:
                    command = await self._read_command(process)
                except ValueError:
                    process.stdout.write("mirage: input too long\\r\\n")  # type: ignore[attr-defined]
                    process.exit(2)  # type: ignore[attr-defined]
                    return
                if command is None:
                    break
                if not command.strip():
                    continue
                if command.strip() in {"exit", "logout"}:
                    break
                output = await self._record_and_execute(process, terminal, factory, command)
                if command.strip() == "clear":
                    process.stdout.write("\\x1b[2J\\x1b[H")  # type: ignore[attr-defined]
                elif output:
                    process.stdout.write(output + "\\r\\n")  # type: ignore[attr-defined]
                await process.stdout.drain()  # type: ignore[attr-defined]
                commands_handled += 1
                if commands_handled >= MAX_COMMANDS_PER_SESSION:
                    process.stdout.write("MIRAGE: session command limit reached.\\r\\n")  # type: ignore[attr-defined]
                    break
            process.exit(0)  # type: ignore[attr-defined]
        except Exception:
            # A failed evidence write must close the channel without a response.
            process.exit(1)  # type: ignore[attr-defined]
        finally:
            self._active_sessions -= 1
