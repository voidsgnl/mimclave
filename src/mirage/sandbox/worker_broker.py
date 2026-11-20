"""Linux Unix-domain-socket event broker for isolated MIRAGE workers.

The broker is the sole component allowed to append worker observations to the
evidence store. This is an IPC transport prototype, not an OS sandbox.
"""

import asyncio
import errno
import json
from collections import deque
import os
from pathlib import Path
import socket
import stat
import struct
import time
from datetime import UTC, datetime
from ipaddress import ip_address
import re
from uuid import UUID

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
MAX_RECENT_SESSIONS = 4096
MAX_SUPERVISOR_MESSAGE_BYTES = 4096


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise WorkerMessageError(f"duplicate supervisor field: {key}")
        result[key] = value
    return result


def encode_supervisor_registration(
    *,
    session_id: str,
    protocol: str,
    source_ip: str,
    source_port: int,
    worker_uid: int,
    worker_pid: int,
) -> bytes:
    """Encode one trusted supervisor registration for the private control socket."""
    try:
        if str(UUID(session_id)) != session_id.lower():
            raise ValueError
    except (ValueError, AttributeError) as exc:
        raise ValueError("session_id must be a canonical UUID") from exc
    if protocol not in {"http", "https", "ssh"}:
        raise ValueError("protocol must be http, https, or ssh")
    normalized_ip = str(ip_address(source_ip))
    if isinstance(source_port, bool) or not isinstance(source_port, int) or not 1 <= source_port <= 65535:
        raise ValueError("source_port must be between 1 and 65535")
    if isinstance(worker_uid, bool) or not isinstance(worker_uid, int) or worker_uid < 0:
        raise ValueError("worker_uid must be a non-negative integer")
    if isinstance(worker_pid, bool) or not isinstance(worker_pid, int) or worker_pid < 1:
        raise ValueError("worker_pid must be a positive integer")
    frame = json.dumps(
        {
            "action": "register",
            "session_id": session_id,
            "protocol": protocol,
            "source_ip": normalized_ip,
            "source_port": source_port,
            "worker_uid": worker_uid,
            "worker_pid": worker_pid,
        },
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8") + b"\n"
    if len(frame) > MAX_SUPERVISOR_MESSAGE_BYTES:
        raise ValueError("supervisor registration exceeds the message size limit")
    return frame


class WorkerBrokerError(RuntimeError):
    """The worker event broker could not safely start or process a message."""


class UnixWorkerEventBroker:
    """Accept bounded worker events and persist them through one evidence owner."""

    def __init__(
        self,
        socket_path: str | Path,
        evidence_store: JsonlEvidenceStore,
        *,
        profile_id: str,
        allowed_uids: set[int] | None = None,
        socket_gid: int | None = None,
        max_clients: int = MAX_BROKER_CLIENTS,
        client_idle_timeout: float = 30.0,
    ) -> None:
        requested_path = Path(socket_path)
        if requested_path.name in {"", ".", ".."}:
            raise ValueError("worker socket path must include a filename")
        try:
            resolved_parent = requested_path.parent.resolve(strict=True)
        except OSError as exc:
            raise WorkerBrokerError("worker socket parent directory must already exist") from exc
        self.socket_path = resolved_parent / requested_path.name
        self.control_socket_path = resolved_parent / (requested_path.name + ".control")
        if not isinstance(profile_id, str) or not re.fullmatch(
            r"[a-z0-9][a-z0-9._-]{0,63}", profile_id
        ):
            raise ValueError("profile_id must be a normalized decoy profile identifier")
        self.profile_id = profile_id
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
        if socket_gid is not None and (
            isinstance(socket_gid, bool) or not isinstance(socket_gid, int) or socket_gid < 0
        ):
            raise ValueError("socket_gid must be a non-negative group ID")
        if socket_gid is not None and allowed_uids is None:
            raise ValueError(
                "allowed_uids must be explicit when a worker socket group is configured"
            )
        if (
            isinstance(client_idle_timeout, bool)
            or not isinstance(client_idle_timeout, (int, float))
            or not 0.1 <= client_idle_timeout <= 3600
        ):
            raise ValueError("client_idle_timeout must be between 0.1 and 3600 seconds")
        self.socket_gid = socket_gid
        self.max_clients = max_clients
        self.client_idle_timeout = float(client_idle_timeout)
        self._server: asyncio.AbstractServer | None = None
        self._control_server: asyncio.AbstractServer | None = None
        self._registrations: dict[str, dict[str, object]] = {}
        self._sequence_guard = WorkerEventSequenceGuard(max_sessions=max_clients)
        self._active_clients = 0
        self._writers: set[asyncio.StreamWriter] = set()
        self._client_tasks: set[asyncio.Task[None]] = set()
        self._recent_session_ids: set[str] = set()
        self._recent_session_order: deque[str] = deque()
        self._commit_lock = asyncio.Lock()
        self._socket_identity: tuple[int, int] | None = None
        self._control_socket_identity: tuple[int, int] | None = None

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
            created_info = os.lstat(self.socket_path)
            self._socket_identity = (created_info.st_dev, created_info.st_ino)
            if self.socket_gid is not None:
                os.chown(self.socket_path, -1, self.socket_gid, follow_symlinks=False)
            socket_mode = 0o600 if self.socket_gid is None else 0o660
            os.chmod(self.socket_path, socket_mode, follow_symlinks=False)
            info = os.lstat(self.socket_path)
            if (
                not stat.S_ISSOCK(info.st_mode)
                or info.st_uid != os.geteuid()
                or (self.socket_gid is not None and info.st_gid != self.socket_gid)
            ):
                raise WorkerBrokerError("created worker socket failed ownership validation")
            if stat.S_IMODE(info.st_mode) != socket_mode:
                raise WorkerBrokerError(f"worker socket permissions must be {socket_mode:04o}")
            self._remove_stale_control_socket()
            self._control_server = await asyncio.start_unix_server(
                self._handle_supervisor,
                path=str(self.control_socket_path),
                limit=MAX_SUPERVISOR_MESSAGE_BYTES + 1,
                backlog=16,
            )
            os.chmod(self.control_socket_path, 0o600, follow_symlinks=False)
            control_info = os.lstat(self.control_socket_path)
            self._control_socket_identity = (control_info.st_dev, control_info.st_ino)
            if (
                not stat.S_ISSOCK(control_info.st_mode)
                or control_info.st_uid != os.geteuid()
                or stat.S_IMODE(control_info.st_mode) != 0o600
            ):
                raise WorkerBrokerError("supervisor control socket failed ownership validation")
        except (OSError, RuntimeError) as exc:
            await self.close()
            if isinstance(exc, WorkerBrokerError):
                raise
            raise WorkerBrokerError(f"could not start worker event broker: {exc}") from exc

    async def close(self) -> None:
        """Stop accepting clients and remove only the socket inode we created."""
        control_server, self._control_server = self._control_server, None
        if control_server is not None:
            control_server.close()
            await control_server.wait_closed()
        server, self._server = self._server, None
        if server is not None:
            server.close()
            await server.wait_closed()
        writers = tuple(self._writers)
        for writer in writers:
            writer.close()
        if writers:
            await asyncio.gather(
                *(writer.wait_closed() for writer in writers),
                return_exceptions=True,
            )
        tasks = tuple(task for task in self._client_tasks if task is not asyncio.current_task())
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        control_identity, self._control_socket_identity = self._control_socket_identity, None
        if control_identity is not None:
            try:
                control_info = os.lstat(self.control_socket_path)
            except FileNotFoundError:
                pass
            else:
                if (
                    stat.S_ISSOCK(control_info.st_mode)
                    and control_info.st_uid == os.geteuid()
                    and (control_info.st_dev, control_info.st_ino) == control_identity
                ):
                    self.control_socket_path.unlink()
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
        mode = stat.S_IMODE(info.st_mode)
        if self.socket_gid is None:
            if mode & 0o077:
                raise WorkerBrokerError(
                    "worker socket directory must have private 0700 permissions"
                )
        elif (
            info.st_gid != self.socket_gid
            or mode & 0o007
            or mode & 0o060
            or not mode & 0o010
        ):
            raise WorkerBrokerError(
                "group worker socket directory must match socket_gid and use owner rwx, "
                "group execute-only, and no world permissions"
            )

    def _remove_stale_socket(self) -> None:
        try:
            info = os.lstat(self.socket_path)
        except FileNotFoundError:
            return
        if (
            not stat.S_ISSOCK(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) not in {0o600, 0o660}
        ):
            raise WorkerBrokerError(
                "refusing to replace an existing non-private or non-socket IPC path"
            )
        expected_mode = 0o600 if self.socket_gid is None else 0o660
        if stat.S_IMODE(info.st_mode) != expected_mode:
            raise WorkerBrokerError("existing worker socket has unexpected permissions")
        if self.socket_gid is not None and info.st_gid != self.socket_gid:
            raise WorkerBrokerError("existing worker socket has unexpected group ownership")
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            probe_result = probe.connect_ex(str(self.socket_path))
        finally:
            probe.close()
        if probe_result == 0:
            raise WorkerBrokerError("another worker event broker is already listening")
        if probe_result != errno.ECONNREFUSED:
            raise WorkerBrokerError(
                "could not prove that the existing worker socket is stale; refusing to replace it"
            )
        current = os.lstat(self.socket_path)
        if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
            raise WorkerBrokerError("worker socket path changed during stale-socket check")
        self.socket_path.unlink()

    def _remove_stale_control_socket(self) -> None:
        try:
            info = os.lstat(self.control_socket_path)
        except FileNotFoundError:
            return
        if (
            not stat.S_ISSOCK(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise WorkerBrokerError("refusing to replace an unsafe supervisor control path")
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            result = probe.connect_ex(str(self.control_socket_path))
        finally:
            probe.close()
        if result == 0:
            raise WorkerBrokerError("another supervisor control socket is already listening")
        if result != errno.ECONNREFUSED:
            raise WorkerBrokerError("could not prove supervisor control socket is stale")
        current = os.lstat(self.control_socket_path)
        if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
            raise WorkerBrokerError("supervisor control socket changed during stale check")
        self.control_socket_path.unlink()

    def _peer_credentials(self, writer: asyncio.StreamWriter) -> tuple[int, int]:
        peer = writer.get_extra_info("socket")
        if peer is None or not hasattr(socket, "SO_PEERCRED"):
            raise WorkerBrokerError("Linux SO_PEERCRED is required for worker authentication")
        try:
            credentials = peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            pid, uid, _ = struct.unpack("3i", credentials)
        except OSError as exc:
            raise WorkerBrokerError("could not authenticate worker peer credentials") from exc
        return pid, uid

    async def _handle_supervisor(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        self._writers.add(writer)
        try:
            _, uid = self._peer_credentials(writer)
            if uid != os.geteuid():
                raise WorkerBrokerError("supervisor UID is not authorized")
            frame = await asyncio.wait_for(
                reader.readuntil(b"\n"), timeout=self.client_idle_timeout
            )
            if len(frame) > MAX_SUPERVISOR_MESSAGE_BYTES:
                raise WorkerMessageError("supervisor message exceeds the size limit")
            payload = json.loads(
                frame[:-1].decode("utf-8"), object_pairs_hook=_unique_json_object
            )
            required = {
                "action", "session_id", "protocol", "source_ip", "source_port",
                "worker_uid", "worker_pid",
            }
            if not isinstance(payload, dict) or set(payload) != required:
                raise WorkerMessageError("invalid supervisor registration fields")
            if payload["action"] != "register":
                raise WorkerMessageError("unsupported supervisor action")
            session_id = payload["session_id"]
            if not isinstance(session_id, str):
                raise WorkerMessageError("session ID must be a UUID")
            if str(UUID(session_id)) != session_id.lower():
                raise WorkerMessageError("session ID must be a canonical UUID")
            protocol = payload["protocol"]
            if not isinstance(protocol, str) or protocol not in {"http", "https", "ssh"}:
                raise WorkerMessageError("unsupported registered protocol")
            source_ip = str(ip_address(payload["source_ip"]))
            source_port = payload["source_port"]
            worker_uid = payload["worker_uid"]
            worker_pid = payload["worker_pid"]
            if isinstance(source_port, bool) or not isinstance(source_port, int) or not 1 <= source_port <= 65535:
                raise WorkerMessageError("invalid registered source port")
            if isinstance(worker_uid, bool) or not isinstance(worker_uid, int) or worker_uid not in self.allowed_uids:
                raise WorkerMessageError("registered worker UID is not allowed")
            if isinstance(worker_pid, bool) or not isinstance(worker_pid, int) or worker_pid < 1:
                raise WorkerMessageError("invalid registered worker PID")
            now = time.monotonic()
            self._registrations = {
                key: value for key, value in self._registrations.items()
                if float(value["expires_at"]) > now
            }
            if session_id in self._registrations or session_id in self._recent_session_ids:
                raise WorkerMessageError("session ID is already registered or has been used")
            if len(self._registrations) >= self.max_clients:
                raise WorkerMessageError("maximum registered sessions reached")
            self._registrations[session_id] = {
                "protocol": protocol,
                "source_ip": source_ip,
                "source_port": source_port,
                "worker_uid": worker_uid,
                "worker_pid": worker_pid,
                "expires_at": now + self.client_idle_timeout,
            }
            writer.write(b'{"registered":true}\n')
            await asyncio.wait_for(writer.drain(), timeout=self.client_idle_timeout)
        except (
            WorkerMessageError, WorkerBrokerError, OSError, ValueError, KeyError, TypeError,
            TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError,
        ):
            try:
                writer.write(b'{"registered":false,"error":"registration rejected"}\n')
                await writer.drain()
            except (ConnectionError, OSError):
                pass
        finally:
            self._writers.discard(writer)
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass

    def _to_session_event(
        self, event: WorkerEvent, registration: dict[str, object] | None = None
    ) -> SessionEvent:
        """Map worker claims to evidence using broker-owned profile and receipt time."""
        timestamp = datetime.now(UTC)
        if registration is None or event.protocol != registration["protocol"]:
            raise WorkerMessageError("event does not match an active supervisor registration")
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

        if registration is not None and event.protocol != registration["protocol"]:
            raise WorkerMessageError("worker protocol does not match supervisor registration")
        return SessionEvent(
            event_id=event.event_id,
            session_id=event.session_id,
            sequence=event.sequence,
            occurred_at=timestamp,
            profile_id=self.profile_id,
            event_type=event.event_type,
            method=method,
            path=path,
            status_code=status_code,
            # Source metadata comes only from the supervisor's accepted client socket.
            source_ip=None if registration is None else str(registration["source_ip"]),
            source_port=None if registration is None else int(registration["source_port"]),
        )

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        self._active_clients += 1
        self._writers.add(writer)
        task = asyncio.current_task()
        if task is not None:
            self._client_tasks.add(task)
        session_id: str | None = None
        try:
            if self._active_clients > self.max_clients:
                raise WorkerBrokerError("maximum worker connections reached")
            peer_pid, peer_uid = self._peer_credentials(writer)
            if peer_uid not in self.allowed_uids:
                raise WorkerBrokerError("worker UID is not authorized")
            while True:
                try:
                    frame = await asyncio.wait_for(
                        reader.readuntil(b"\n"), timeout=self.client_idle_timeout
                    )
                except TimeoutError:
                    break
                except asyncio.IncompleteReadError as exc:
                    if exc.partial:
                        raise WorkerMessageError(
                            "worker disconnected with an incomplete frame"
                        ) from exc
                    break
                except asyncio.LimitOverrunError as exc:
                    raise WorkerMessageError(
                        "worker frame exceeds the configured size limit"
                    ) from exc
                if len(frame) > MAX_WORKER_MESSAGE_BYTES:
                    raise WorkerMessageError("worker frame exceeds the configured size limit")
                event = decode_worker_event(frame)
                first_event = session_id is None
                if first_event:
                    registration = self._registrations.get(event.session_id)
                    if registration is None:
                        raise WorkerMessageError("worker session was not registered")
                    if (
                        registration["worker_uid"] != peer_uid
                        or registration["worker_pid"] != peer_pid
                        or registration["protocol"] != event.protocol
                        or registration.get("claimed", False)
                    ):
                        raise WorkerMessageError("worker identity does not match registration")
                    session_id = event.session_id
                    if session_id in self._recent_session_ids:
                        raise WorkerMessageError("worker session ID has already been used")
                elif event.session_id != session_id:
                    raise WorkerMessageError(
                        "one worker connection must use exactly one session ID"
                    )

                registration = self._registrations.get(event.session_id)
                if registration is None or float(registration["expires_at"]) <= time.monotonic():
                    raise WorkerMessageError("worker session registration expired")
                session_event = self._to_session_event(event, registration)
                async with self._commit_lock:
                    self._sequence_guard.validate(event)
                    await asyncio.to_thread(self.evidence_store.append, session_event)
                    self._sequence_guard.accept(event)
                    if first_event:
                        registration["claimed"] = True
                        self._recent_session_ids.add(event.session_id)
                        self._recent_session_order.append(event.session_id)
                        if len(self._recent_session_order) > MAX_RECENT_SESSIONS:
                            expired = self._recent_session_order.popleft()
                            self._recent_session_ids.discard(expired)
                writer.write(
                    json.dumps(
                        {"accepted": True, "event_id": event.event_id, "sequence": event.sequence},
                        separators=(",", ":"),
                    ).encode("ascii") + b"\n"
                )
                await asyncio.wait_for(
                    writer.drain(), timeout=self.client_idle_timeout
                )
        except (WorkerMessageError, WorkerBrokerError, EvidenceStoreError, OSError, ValueError):
            # Do not disclose filesystem paths, evidence contents, or internal errors.
            try:
                writer.write(b'{"accepted":false,"error":"event rejected"}\n')
                await writer.drain()
            except (ConnectionError, OSError):
                pass
        finally:
            if session_id is not None:
                self._sequence_guard.close_session(session_id)
                self._registrations.pop(session_id, None)
            self._active_clients = max(0, self._active_clients - 1)
            self._writers.discard(writer)
            if task is not None:
                self._client_tasks.discard(task)
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass
