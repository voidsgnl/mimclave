"""Immutable configuration models.

These models describe intended configuration only; they do not open sockets or
change host networking.
"""

from dataclasses import dataclass
from enum import StrEnum


class Protocol(StrEnum):
    SSH = "ssh"
    HTTP = "http"
    HTTPS = "https"
    FTP = "ftp"
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    SMB = "smb"
    RDP = "rdp"
    REDIS = "redis"
    CUSTOM = "custom"


@dataclass(frozen=True, slots=True)
class Endpoint:
    host: str
    port: int
    transport: str = "tcp"

    def __post_init__(self) -> None:
        if not self.host.strip():
            raise ValueError("endpoint host must not be empty")
        if not 1 <= self.port <= 65535:
            raise ValueError("endpoint port must be between 1 and 65535")
        if self.transport.lower() not in {"tcp", "udp"}:
            raise ValueError("transport must be tcp or udp")
        object.__setattr__(self, "transport", self.transport.lower())


@dataclass(frozen=True, slots=True)
class DecoyProfile:
    profile_id: str
    name: str
    protocol: Protocol
    service_name: str
    service_version: str
    hostname: str

    def __post_init__(self) -> None:
        for field_name in ("profile_id", "name", "service_name", "service_version", "hostname"):
            if not getattr(self, field_name).strip():
                raise ValueError(f"{field_name} must not be empty")


@dataclass(frozen=True, slots=True)
class ProtectedService:
    """Inventory record for a real service; never exposed as a decoy identity."""

    service_id: str
    endpoint: Endpoint
    description: str = ""


@dataclass(frozen=True, slots=True)
class ListenerMapping:
    """Maps an exposed listener to an independently defined decoy profile."""

    listener: Endpoint
    profile_id: str
    allow_nonstandard_protocol: bool = False
    override_reason: str | None = None

    def __post_init__(self) -> None:
        if not self.profile_id.strip():
            raise ValueError("profile_id must not be empty")
        if self.allow_nonstandard_protocol and not (self.override_reason or "").strip():
            raise ValueError("a documented override_reason is required for nonstandard mappings")
        if not self.allow_nonstandard_protocol and self.override_reason is not None:
            raise ValueError("override_reason is only valid when nonstandard mapping is enabled")
