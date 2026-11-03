"""Read-only Linux listening-socket discovery via /proc/net.

No active network probes, subprocesses, privilege escalation, or host changes
are performed. Process ownership is intentionally not inferred in this first
iteration.
"""

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path


@dataclass(frozen=True, slots=True)
class Listener:
    address: str
    port: int
    transport: str
    family: str


def _decode_address(raw: str, family: str) -> str:
    if family == "ipv4":
        return str(IPv4Address(bytes.fromhex(raw)[::-1]))
    if family == "ipv6":
        # Linux renders IPv6 as four host-endian 32-bit words.
        raw_bytes = bytes.fromhex(raw)
        normalized = b"".join(
            raw_bytes[index : index + 4][::-1] for index in range(0, 16, 4)
        )
        return str(IPv6Address(normalized))
    raise ValueError(f"unsupported address family: {family}")


def parse_proc_net_table(contents: str, family: str, transport: str = "tcp") -> list[Listener]:
    """Parse a /proc/net/{tcp,tcp6,udp,udp6} table into listening endpoints."""
    listeners: list[Listener] = []
    lines = contents.splitlines()
    for line in lines[1:]:
        fields = line.split()
        if len(fields) < 4:
            continue
        local = fields[1]
        state = fields[3]
        # TCP LISTEN is 0A. UDP has no LISTEN state; report bound sockets
        # (00007) separately as candidates rather than claiming they listen.
        if transport == "tcp" and state != "0A":
            continue
        if transport == "udp" and state != "07":
            continue
        try:
            raw_address, raw_port = local.rsplit(":", 1)
            address = _decode_address(raw_address, family)
            port = int(raw_port, 16)
        except (ValueError, IndexError):
            continue
        if port:
            listeners.append(Listener(address, port, transport, family))
    return listeners


def discover_proc_listeners(proc_net: Path = Path("/proc/net")) -> list[Listener]:
    """Return TCP listeners and bound UDP sockets visible to the current user."""
    results: list[Listener] = []
    tables = (
        ("tcp", "ipv4", "tcp"),
        ("tcp6", "ipv6", "tcp"),
        ("udp", "ipv4", "udp"),
        ("udp6", "ipv6", "udp"),
    )
    for filename, family, transport in tables:
        path = proc_net / filename
        try:
            contents = path.read_text(encoding="ascii")
        except (FileNotFoundError, PermissionError, OSError):
            continue
        results.extend(parse_proc_net_table(contents, family, transport))
    return sorted(results, key=lambda item: (item.transport, item.family, item.address, item.port))
