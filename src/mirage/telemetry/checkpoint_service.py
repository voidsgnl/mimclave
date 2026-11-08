"""Durable checkpoint service intended for a separately administered host.

The HTTP listener is loopback-only. Put a TLS-terminating reverse proxy in
front of it, and keep its database, token, backups, and administration outside
the evidence host's trust boundary.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import sqlite3
import stat
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from mirage.telemetry.checkpoints import (
    CheckpointConflictError,
    EvidenceCheckpoint,
)

_MAX_BODY_BYTES = 4096


def _etag(checkpoint: EvidenceCheckpoint) -> str:
    payload = json.dumps(
        asdict(checkpoint), sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return f'"{hashlib.sha256(payload).hexdigest()}"'


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _decode_checkpoint(data: bytes) -> EvidenceCheckpoint:
    payload = json.loads(data, object_pairs_hook=_reject_duplicate_keys)
    if not isinstance(payload, dict) or set(payload) != {
        "generation", "record_count", "head_hash"
    }:
        raise ValueError("checkpoint must contain exactly generation, record_count, head_hash")
    if (
        isinstance(payload["generation"], bool)
        or not isinstance(payload["generation"], int)
        or isinstance(payload["record_count"], bool)
        or not isinstance(payload["record_count"], int)
        or not isinstance(payload["head_hash"], str)
    ):
        raise ValueError("checkpoint fields have invalid types")
    return EvidenceCheckpoint(**payload)


class _CheckpointDatabase:
    """SQLite-backed singleton checkpoint with FULL synchronous commits."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        parent = self.path.parent
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        parent_info = parent.lstat()
        if (
            not stat.S_ISDIR(parent_info.st_mode)
            or stat.S_IMODE(parent_info.st_mode) & 0o077
        ):
            raise ValueError("checkpoint database directory must be private and not a symlink")

        try:
            info = self.path.lstat()
        except FileNotFoundError:
            fd = os.open(
                self.path,
                os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
            self._fsync_parent()
            info = self.path.lstat()

        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise ValueError(
                "checkpoint database must be a private regular file without hard links"
            )

        connection = self._connect()
        try:
            connection.execute("PRAGMA journal_mode=DELETE")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS checkpoint (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    generation INTEGER NOT NULL,
                    record_count INTEGER NOT NULL,
                    head_hash TEXT NOT NULL
                )
                """
            )
            connection.commit()
        finally:
            connection.close()

        os.chmod(self.path, 0o600)
        fd = os.open(self.path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        self._fsync_parent()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5.0, isolation_level=None)
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA busy_timeout=5000")
        return connection

    def _fsync_parent(self) -> None:
        fd = os.open(self.path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def read(self) -> tuple[EvidenceCheckpoint | None, str | None]:
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT generation, record_count, head_hash FROM checkpoint WHERE singleton = 1"
            ).fetchone()
        finally:
            connection.close()
        if row is None:
            return None, None
        checkpoint = EvidenceCheckpoint(*row)
        return checkpoint, _etag(checkpoint)

    def compare_and_set(
        self,
        checkpoint: EvidenceCheckpoint,
        *,
        expected_etag: str | None,
    ) -> str:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT generation, record_count, head_hash FROM checkpoint WHERE singleton = 1"
            ).fetchone()
            current = None if row is None else EvidenceCheckpoint(*row)
            current_etag = None if current is None else _etag(current)
            if current_etag != expected_etag:
                raise CheckpointConflictError("checkpoint conditional request did not match")

            if current is None:
                if checkpoint.generation != 1:
                    raise CheckpointConflictError("initial checkpoint generation must be 1")
                connection.execute(
                    "INSERT INTO checkpoint VALUES (1, ?, ?, ?)",
                    (checkpoint.generation, checkpoint.record_count, checkpoint.head_hash),
                )
            else:
                if (
                    checkpoint.generation != current.generation + 1
                    or checkpoint.record_count <= current.record_count
                ):
                    raise CheckpointConflictError(
                        "checkpoint generation and record count must increase monotonically"
                    )
                connection.execute(
                    """
                    UPDATE checkpoint
                    SET generation = ?, record_count = ?, head_hash = ?
                    WHERE singleton = 1
                    """,
                    (checkpoint.generation, checkpoint.record_count, checkpoint.head_hash),
                )
            connection.commit()
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()
        return _etag(checkpoint)


def create_checkpoint_server(
    *,
    database_path: str | Path,
    bearer_token: str,
    host: str = "127.0.0.1",
    port: int = 8080,
    resource_path: str = "/v1/mirage/checkpoint",
) -> ThreadingHTTPServer:
    """Create a loopback-only HTTP server for a TLS reverse proxy to front."""
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError("checkpoint service host must be a literal loopback IP") from exc
    if not address.is_loopback or address.version != 4:
        raise ValueError("checkpoint service must bind only to an IPv4 loopback IP")
    if not 0 <= port <= 65535:
        raise ValueError("checkpoint service port is outside the valid range")
    if (
        not bearer_token
        or bearer_token.strip() != bearer_token
        or any(ord(char) < 0x21 or ord(char) == 0x7F for char in bearer_token)
    ):
        raise ValueError("checkpoint bearer token must be non-empty and contain no whitespace")
    if (
        not resource_path.startswith("/")
        or "?" in resource_path
        or "#" in resource_path
    ):
        raise ValueError(
            "checkpoint resource path must be an absolute path without query or fragment"
        )

    database = _CheckpointDatabase(database_path)

    class Handler(BaseHTTPRequestHandler):
        server_version = "MIRAGECheckpoint/1"
        sys_version = ""
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args: Any) -> None:
            # Never log request headers or bearer credentials.
            return

        def _send(self, status: int, body: bytes = b"", etag: str | None = None) -> None:
            self.close_connection = True
            self.send_response(status)
            if body:
                self.send_header("Content-Type", "application/json")
            if etag is not None:
                self.send_header("ETag", etag)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if body:
                self.wfile.write(body)

        def _authorized(self) -> bool:
            supplied = self.headers.get("Authorization", "")
            expected = f"Bearer {bearer_token}"
            if not hmac.compare_digest(
                supplied.encode("utf-8"), expected.encode("utf-8")
            ):
                self._send(401, b'{"error":"unauthorized"}')
                return False
            return True

        def _path_ok(self) -> bool:
            if self.path != resource_path:
                self._send(404, b'{"error":"not found"}')
                return False
            return True

        def do_GET(self) -> None:
            if not self._path_ok() or not self._authorized():
                return
            try:
                checkpoint, tag = database.read()
            except sqlite3.Error:
                self._send(503, b'{"error":"checkpoint storage unavailable"}')
                return
            if checkpoint is None:
                self._send(404, b'{"error":"checkpoint not initialized"}')
                return
            body = json.dumps(
                asdict(checkpoint), sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
            self._send(200, body, tag)

        def do_PUT(self) -> None:
            if not self._path_ok() or not self._authorized():
                return
            if self.headers.get("Transfer-Encoding") is not None:
                self._send(400, b'{"error":"transfer encoding is not supported"}')
                return
            content_type = (
                self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
            )
            if content_type != "application/json":
                self._send(415, b'{"error":"application/json required"}')
                return
            raw_length = self.headers.get("Content-Length")
            if raw_length is None or not raw_length.isdecimal():
                self._send(400, b'{"error":"valid content length required"}')
                return
            length = int(raw_length)
            if length < 1:
                self._send(400, b'{"error":"empty request body"}')
                return
            if length > _MAX_BODY_BYTES:
                self._send(413, b'{"error":"request body too large"}')
                return
            body = self.rfile.read(length)
            if len(body) != length:
                self._send(400, b'{"error":"incomplete request body"}')
                return
            try:
                checkpoint = _decode_checkpoint(body)
            except (ValueError, TypeError, json.JSONDecodeError):
                self._send(400, b'{"error":"invalid checkpoint"}')
                return

            if_match = self.headers.get("If-Match")
            if_none_match = self.headers.get("If-None-Match")
            if if_none_match == "*" and if_match is None:
                expected_etag = None
            elif if_match is not None and if_none_match is None:
                expected_etag = if_match
            else:
                self._send(400, b'{"error":"exactly one conditional header is required"}')
                return

            try:
                tag = database.compare_and_set(
                    checkpoint, expected_etag=expected_etag
                )
            except CheckpointConflictError:
                self._send(412, b'{"error":"checkpoint precondition failed"}')
                return
            except sqlite3.Error:
                self._send(503, b'{"error":"checkpoint storage unavailable"}')
                return
            response = json.dumps(
                asdict(checkpoint), sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
            self._send(200, response, tag)

        def do_POST(self) -> None:
            self._send(405, b'{"error":"method not allowed"}')

        def do_DELETE(self) -> None:
            self._send(405, b'{"error":"method not allowed"}')

    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    return server


def main() -> None:
    token = os.environ.get("MIRAGE_CHECKPOINT_TOKEN")
    if not token:
        raise SystemExit("MIRAGE_CHECKPOINT_TOKEN must be set")
    os.umask(0o077)
    database_path = os.environ.get(
        "MIRAGE_CHECKPOINT_DB", "/var/lib/mirage-checkpoint/checkpoint.sqlite3"
    )
    host = os.environ.get("MIRAGE_CHECKPOINT_HOST", "127.0.0.1")
    port = int(os.environ.get("MIRAGE_CHECKPOINT_PORT", "8080"))
    resource_path = os.environ.get(
        "MIRAGE_CHECKPOINT_PATH", "/v1/mirage/checkpoint"
    )
    server = create_checkpoint_server(
        database_path=database_path,
        bearer_token=token,
        host=host,
        port=port,
        resource_path=resource_path,
    )
    print(f"MIRAGE checkpoint service listening on {host}:{port}{resource_path}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
