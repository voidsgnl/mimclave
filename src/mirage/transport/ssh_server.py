"""Loopback-only SSH transport for the in-memory virtual terminal.

AsyncSSH handles SSH protocol and cryptography. MIRAGE handles terminal input
through a bounded callback and never invokes a host shell or filesystem.
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
COMMAND_TIMEOUT = 30.0
PROMPT = "{username}@{hostname}:{cwd}$ "

_SSH_BASE = asyncssh.SSHServer if asyncssh is not None else object
_SESSION_BASE = asyncssh.SSHServerSession if asyncssh is not None else object


class _NoAuthSSHServer(_SSH_BASE):  # type: ignore[misc,valid-type]
    """Accept SSH sessions without credentials and deny forwarding."""

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

    def session_requested(self) -> object:
        if self._owner._active_sessions >= self._owner.max_sessions:
            return False
        self._owner._active_sessions += 1
        return _VirtualTerminalSession(self._owner)

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


class _VirtualTerminalSession(_SESSION_BASE):  # type: ignore[misc,valid-type]
    """A callback-driven SSH session with bounded input and private virtual state."""

    def __init__(self, owner: "SSHDecoyServer") -> None:
        self._owner = owner
        self._channel = None
        self._terminal = VirtualTerminal()
        self._events = SessionEventFactory(owner.profile_id)
        self._mode: str | None = None
        self._exec_command: str | None = None
        self._buffer = ""
        self._last_was_cr = False
        self._commands = 0
        self._source_ip: str | None = None
        self._source_port: int | None = None
        self._idle_handle: asyncio.TimerHandle | None = None
        self._line_handle: asyncio.TimerHandle | None = None
        self._closed = False

    def connection_made(self, channel: object) -> None:
        self._channel = channel
        peer = channel.get_extra_info("peername")  # type: ignore[attr-defined]
        if isinstance(peer, tuple) and peer:
            self._source_ip = str(peer[0])
            self._source_port = int(peer[1]) if len(peer) > 1 else None

    def pty_requested(
        self, term_type: str, term_size: tuple[int, int, int, int],
        term_modes: dict[int, int],
    ) -> bool:
        del term_type, term_size, term_modes
        return True

    def shell_requested(self) -> bool:
        self._mode = "shell"
        return True

    def exec_requested(self, command: str) -> bool:
        self._mode = "exec"
        self._exec_command = command
        return True

    def subsystem_requested(self, subsystem: str) -> bool:
        del subsystem
        return False

    def session_started(self) -> None:
        if self._mode == "exec":
            self._execute_exec()
            return
        self._write(
            "MIRAGE virtual terminal — simulated data only; no host commands execute.\r\n"
        )
        self._write_prompt()
        self._arm_idle_timeout()

    def data_received(self, data: str | bytes, datatype: object) -> None:
        del datatype
        if self._closed or self._mode != "shell":
            return
        if isinstance(data, bytes):
            data = data.decode("utf-8", errors="replace")
        self._arm_idle_timeout()
        for char in data:
            if char == "\n" and self._last_was_cr:
                self._last_was_cr = False
                continue
            self._last_was_cr = char == "\r"
            if char in ("\r", "\n"):
                self._cancel_line_timeout()
                self._write("\r\n")
                self._execute_line(self._buffer)
                self._buffer = ""
                if self._closed:
                    return
                if self._commands >= MAX_COMMANDS_PER_SESSION:
                    self._write("MIRAGE: session command limit reached.\r\n")
                    self._finish(0)
                    return
                self._write_prompt()
                self._arm_idle_timeout()
            elif char in ("\x08", "\x7f"):
                if self._buffer:
                    self._buffer = self._buffer[:-1]
                    self._write("\\b \\b")
            elif char.isprintable():
                if not self._buffer:
                    self._arm_line_timeout()
                if len(self._buffer) >= MAX_COMMAND_LENGTH:
                    self._write("\r\nmirage: input too long\r\n")
                    self._finish(2)
                    return
                self._buffer += char
                self._write(char)

    def connection_lost(self, exc: Exception | None) -> None:
        del exc
        self._cancel_timeouts()
        if not self._closed:
            self._closed = True
            self._owner._active_sessions -= 1

    def _execute_exec(self) -> None:
        command = self._exec_command or ""
        if len(command) > MAX_COMMAND_LENGTH:
            self._write("mirage: input too long\r\n")
            self._finish(2)
            return
        self._execute_line(command)
        if not self._closed:
            self._finish(0)

    def _execute_line(self, command: str) -> None:
        if not command.strip():
            return
        if command.strip() in {"exit", "logout"}:
            self._finish(0)
            return
        identifier = self._command_identifier(command)
        event = self._events.record_terminal_command(
            command_name=identifier,
            source_ip=self._source_ip,
            source_port=self._source_port,
        )
        try:
            # Persist and fsync the redacted event before returning any output.
            self._owner.event_sink(event)
        except Exception:
            self._finish(1)
            return

        try:
            output = self._terminal.execute(command)
        except Exception:
            self._finish(1)
            return
        self._commands += 1
        if command.strip() == "clear":
            self._write("\x1b[2J\x1b[H")
        elif output:
            self._write(output + "\r\n")

    @staticmethod
    def _command_identifier(command: str) -> str:
        parts = command.strip().split(maxsplit=1)
        if not parts:
            return "empty"
        candidate = parts[0].lower()
        return candidate if re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", candidate) else "other"

    def _write(self, value: str) -> None:
        if self._channel is not None and not self._closed:
            self._channel.write(value)  # type: ignore[attr-defined]

    def _write_prompt(self) -> None:
        self._write(
            PROMPT.format(
                username=self._terminal.username,
                hostname=self._terminal.hostname,
                cwd=self._terminal.cwd,
            )
        )

    def _arm_idle_timeout(self) -> None:
        self._cancel_idle_timeout()
        self._idle_handle = asyncio.get_running_loop().call_later(
            self._owner.idle_timeout, self._on_idle
        )

    def _arm_line_timeout(self) -> None:
        self._cancel_line_timeout()
        self._line_handle = asyncio.get_running_loop().call_later(
            self._owner.idle_timeout, self._on_line_timeout
        )

    def _cancel_idle_timeout(self) -> None:
        if self._idle_handle is not None:
            self._idle_handle.cancel()
            self._idle_handle = None

    def _cancel_line_timeout(self) -> None:
        if self._line_handle is not None:
            self._line_handle.cancel()
            self._line_handle = None

    def _cancel_timeouts(self) -> None:
        self._cancel_idle_timeout()
        self._cancel_line_timeout()

    def _on_idle(self) -> None:
        self._write("\r\nMIRAGE: idle session closed.\r\n")
        self._finish(0)

    def _on_line_timeout(self) -> None:
        self._write("\r\nmirage: command input timed out\r\n")
        self._finish(2)

    def _finish(self, status: int) -> None:
        if self._closed:
            return
        self._closed = True
        self._cancel_timeouts()
        self._owner._active_sessions -= 1
        if self._channel is not None:
            self._channel.exit(status)  # type: ignore[attr-defined]


class SSHDecoyServer:
    """A bounded SSH front-end to per-channel in-memory virtual terminals."""

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
        idle_timeout: float = COMMAND_TIMEOUT,
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
        """Stop accepting SSH clients and close active connections."""
        if self._server is None:
            return
        server, self._server = self._server, None
        server.close()  # type: ignore[attr-defined]
        await server.wait_closed()  # type: ignore[attr-defined]
        connections = tuple(self._connections)
        for connection in connections:
            connection.close()  # type: ignore[attr-defined]
        if connections:
            waiters = [
                connection.wait_closed() for connection in connections
            ]  # type: ignore[attr-defined]
            await asyncio.gather(*waiters, return_exceptions=True)
