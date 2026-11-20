"""Trusted supervisor client for registering worker sessions with the evidence broker.

This module only performs registration. It does not launch workers or provide
operating-system isolation.
"""

import asyncio
import json
from pathlib import Path

from mirage.sandbox.worker_broker import (
    MAX_SUPERVISOR_MESSAGE_BYTES,
    encode_supervisor_registration,
)


class SupervisorRegistrationError(RuntimeError):
    """The evidence broker rejected or could not confirm a worker registration."""


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise SupervisorRegistrationError("broker returned an ambiguous response")
        result[key] = value
    return result


async def register_worker_session(
    control_socket_path: str | Path,
    *,
    session_id: str,
    protocol: str,
    source_ip: str,
    source_port: int,
    worker_uid: int,
    worker_pid: int,
    timeout: float = 3.0,
) -> None:
    """Register a worker after the supervisor accepts its original client socket.

    The caller must obtain source_ip/source_port from that accepted socket and
    must register the exact worker UID/PID that will connect to the event socket.
    """
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not 0.1 <= timeout <= 30.0
    ):
        raise ValueError("timeout must be between 0.1 and 30 seconds")

    frame = encode_supervisor_registration(
        session_id=session_id,
        protocol=protocol,
        source_ip=source_ip,
        source_port=source_port,
        worker_uid=worker_uid,
        worker_pid=worker_pid,
    )
    writer: asyncio.StreamWriter | None = None
    try:
        async with asyncio.timeout(float(timeout)):
            reader, writer = await asyncio.open_unix_connection(str(control_socket_path))
            writer.write(frame)
            await writer.drain()
            response = await reader.readline()
            if not response or len(response) > MAX_SUPERVISOR_MESSAGE_BYTES:
                raise SupervisorRegistrationError("broker returned no valid registration response")
            decoded = json.loads(
                response.decode("utf-8", errors="strict"),
                object_pairs_hook=_unique_object,
                parse_constant=lambda _value: (_ for _ in ()).throw(
                    SupervisorRegistrationError("broker returned an invalid response")
                ),
            )
            if decoded != {"registered": True}:
                raise SupervisorRegistrationError("broker rejected worker registration")
    except SupervisorRegistrationError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, TimeoutError) as exc:
        raise SupervisorRegistrationError("could not confirm worker registration") from exc
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass
