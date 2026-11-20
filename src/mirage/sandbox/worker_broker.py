"""Linux Unix-domain-socket event broker for isolated MIRAGE workers.

The broker is the sole component allowed to append worker observations to the
evidence store. This is an IPC transport prototype, not an OS sandbox.
"""

import asyncio
import json
import os
from pathlib import Path
import socket
import stat
import struct
from datetime import datetime
from typing import Any

from mirage.sandbox.ipc import (
    MAX_WORKER_MESSAGE_BYTES,
    WorkerEvent,
    WorkerEventSequenceGuard,
    WorkerMessageError,
    decode_worker_event,
)
from mirage.telemetry.events import SessionEvent
from mirage.telemetry.store import EvidenceStoreError, JsonlEvidenceStore

MAX_BROKER_CLIENTS = 64
ACK_BYTES = 256


class WorkerBrokerError(RuntimeError):
    """The worker event broker could not safely start or process a message."""


class UnixWorkerEventBroker:
    """Accept bounded worker events and persist them through one evidence owner."""

    def __init__(
        self,
        socket_path: str | Path,
        evidence_store: JsonlEvidenceStore,
        *,
        allowed_uids: set[int] | None = None,
        max_clients: int = MAX_BROKER_CLIENTS,
    ) -> None:
        requested_path = Path(socket_path)
        if requested_path.name in {"", ".", ".."}:
            raise ValueError("worker socket path must include a filename")
        try:
            resolved_parent = requested_path.parent.resolve(strict=True)
        except OSError as exc:
            raise WorkerBrokerError("worker socket parent directory must already exist") from exc
        self.socket_path = resolved_parent / requested_path.name
        self.evidence_store = evidence_store
        self.allowed_uids = frozenset(
            {os.geteuid()} if allowed_uids is None else allowed_uids
        )
        if not self.allowed_uids or any(
            isinstance(uid, bool) or not isinstance(uid, int) or uid < 0
            for uid in self.allowed_uids
        ):
            raise ValueError("allowed_uids must contain one or more non-negative UIDs")
        if isinstance(max_clients, bool) or not isinstance(max_clients, int):
            raise ValueError("max_clients must be an integer")
        if not 1 <= max_clients <= MAX_BROKER_CLIENTS:
            raise ValueError(f"max_clients must be between 1 and {MAX_BROKER_CLIENTS}")
        self.max_clients = max_clients
        self._server: asyncio.AbstractServer | None = None
        self._sequence_guard = WorkerEventSequenceGuard(max_sessions=max_clients)
        self._active_clients = 0
        self._commit_lock = asyncio.Lock()
        self._socket_identity: tuple[int, int] | None = None

    async def start(self) -> None:
        """Start on a private, owner-controlled directory and a private socket."""
        if self._server is not None:
            raise WorkerBrokerError("worker event broker is already running")
        self._validate_parent()
        self._remove_stale_socket()
        try:
            self._server = await asyncio.start_unix_server(
                self._handle_client,
                path=str(self.socket_path),
                limit=MAX_WORKER_MESSAGE_BYTES + 1,
                backlog=self.max_clients,
            )
            os.chmod(self.socket_path, 0o600, follow_symlinks=False)
            info = os.lstat(self.socket_path)
            if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.geteuid():
                raise WorkerBrokerError("created worker socket failed ownership validation")
            if stat.S_IMODE(info.st_mode) != 0o600:
                raise WorkerBrokerError("worker socket permissions must be 0600")
            self._socket_identity = (info.st_dev, info.st_ino)
        except (OSError, RuntimeError) as exc:
            await self.close()
            if isinstance(exc, WorkerBrokerError):
                raise
            raise WorkerBrokerError(f"could not start worker event broker: {exc}") from exc

    async def close(self) -> None:
        """Stop accepting clients and remove only the socket inode we created."""
        server, self._server = self._server, None
        if server is not None:
            server.close()
            await server.wait_closed()
        identity, self._socket_identity = self._socket_identity, None
        if identity is None:
            return
        try:
            info = os.lstat(self.socket_path)
        except FileNotFoundError:
            return
        if (
            stat.S_ISSOCK(info.st_mode)
            and info.st_uid == os.geteuid()
            and (info.st_dev, info.st_ino) == identity
        ):
            self.socket_path.unlink()

    def _validate_parent(self) -> None:
        parent = self.socket_path.parent
        try:
            info = os.lstat(parent)
        except OSError as exc:
            raise WorkerBrokerError(f"worker socket directory is unavailable: {exc}") from exc
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise WorkerBrokerError("worker socket parent must be a real directory")
        if info.st_uid != os.geteuid():
            raise WorkerBrokerError("worker socket directory must be owned by the broker UID")
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise WorkerBrokerError("worker socket directory must have private 0700 permissions")

    def _remove_stale_socket(self) -> None:
        try:
            info = os.lstat(self.socket_path)
        except FileNotFoundError:
            return
        if (
            not stat.S_ISSOCK(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise WorkerBrokerError(
                "refusing to replace an existing non-private or non-socket IPC path"
            )
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            if probe.connect_ex(str(self.socket_path)) == 0:
                raise WorkerBrokerError("another worker event broker is already listening")
        finally:
            probe.close()
        current = os.lstat(self.socket_path)
        if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
            raise WorkerBrokerError("worker socket path changed during stale-socket check")
        self.socket_path.unlink()

    def _peer_uid(self, writer: asyncio.StreamWriter) -> int:
        peer = writer.get_extra_info("socket")
        if peer is None or not hasattr(socket, "SO_PEERCRED"):
            raise WorkerBrokerError("Linux SO_PEERCRED is required for worker authentication")
        try:
            credentials = peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            _, uid, _ = struct.unpack("3i", credentials)
        except OSError as exc:
            raise WorkerBrokerError("could not authenticate worker peer credentials") from exc
        if uid not in self.allowed_uids:
            raise WorkerBrokerError("worker UID is not authorized")
        return uid

    @staticmethod
    def _to_session_event(event: WorkerEvent) -> SessionEvent:
        """Map only supported, credential-free observations to evidence schema."""
        timestamp = datetime.fromisoformat(event.timestamp.replace("Z", "+00:00"))
        if event.protocol in {"http", "https"}:
            if (
                event.event_type != "http.request"
                or event.method is None
                or event.request_path is None
                or event.status_code is None
            ):
                raise WorkerMessageError("HTTP events require method, path, and status metadata")
            method = event.method
            path = event.request_path
            status_code = event.status_code
        elif event.protocol == "ssh":
            if event.event_type != "ssh.command" or event.command_name is None:
                raise WorkerMessageError("SSH events require normalized command metadata")
            method = "SSH"
            path = f"/terminal/{event.command_name}"
            status_code = event.status_code or 200
        else:
            raise WorkerMessageError("unsupported worker protocol")

        return SessionEvent(
            event_id=event.event_id,
            session_id=event.session_id,
            sequence=event.sequence,
            occurred_at=timestamp,
            profile_id=event.profile_id,
            event_type=event.event_type,
            method=method,
            path=path,
            status_code=status_code,
            source_ip=event.source_ip,
            source_port=event.source_port,
        )

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        self._active_clients += 1
        session_id: str | None = None
        try:
            if self._active_clients > self.max_clients:
                raise WorkerBrokerError("maximum worker connections reached")
            self._peer_uid(writer)
            while True:
                try:
                    frame = await reader.readuntil(b"\n")
                except asyncio.IncompleteReadError as exc:
                    if exc.partial:
                        raise WorkerMessageError("worker disconnected with an incomplete frame")
                    break
                except asyncio.LimitOverrunError as exc:
                    raise WorkerMessageError("worker frame exceeds the configured size limit") from exc
                if len(frame) > MAX_WORKER_MESSAGE_BYTES:
                    raise WorkerMessageError("worker frame exceeds the configured size limit")
                event = decode_worker_event(frame)
                if session_id is None:
                    session_id = event.session_id
                elif event.session_id != session_id:
                    raise WorkerMessageError("one worker connection must use exactly one session ID")

                session_event = self._to_session_event(event)
                async with self._commit_lock:
                    self._sequence_guard.validate(event)
                    await asyncio.to_thread(self.evidence_store.append, session_event)
                    self._sequence_guard.accept(event)
                writer.write(
                    json.dumps(
                        {"accepted": True, "event_id": event.event_id, "sequence": event.sequence},
                        separators=(",", ":"),
                    ).encode("ascii") + b"\n"
                )
                await writer.drain()
        except (WorkerMessageError, WorkerBrokerError, EvidenceStoreError, OSError) as exc:
            # Do not disclose filesystem paths, evidence contents, or internal errors.
            try:
                writer.write(b'{"accepted":false,"error":"event rejected"}\n')
                await writer.drain()
            except (ConnectionError, OSError):
                pass
        finally:
            if session_id is not None:
                self._sequence_guard.close_session(session_id)
            self._active_clients = max(0, self._active_clients - 1)
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass
