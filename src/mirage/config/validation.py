"""Validation for listener-to-decoy protocol compatibility."""

from dataclasses import dataclass

from mirage.config.models import DecoyProfile, ListenerMapping, Protocol

# These are conventional expectations, not immutable port assignments.
# Unknown ports intentionally have no default expectation.
DEFAULT_PORT_PROTOCOLS: dict[int, Protocol] = {
    21: Protocol.FTP,
    22: Protocol.SSH,
    80: Protocol.HTTP,
    443: Protocol.HTTPS,
    445: Protocol.SMB,
    3306: Protocol.MYSQL,
    3389: Protocol.RDP,
    5432: Protocol.POSTGRESQL,
    6379: Protocol.REDIS,
}


@dataclass(frozen=True, slots=True)
class ValidationIssue:
    code: str
    message: str


class ConfigurationError(ValueError):
    """Raised when a mapping references an absent profile or violates policy."""


def validate_mapping(
    mapping: ListenerMapping,
    profiles: dict[str, DecoyProfile],
) -> list[ValidationIssue]:
    profile = profiles.get(mapping.profile_id)
    if profile is None:
        raise ConfigurationError(f"unknown decoy profile: {mapping.profile_id}")

    expected = DEFAULT_PORT_PROTOCOLS.get(mapping.listener.port) if mapping.listener.transport == "tcp" else None
    if expected is None or profile.protocol == expected:
        return []

    if mapping.allow_nonstandard_protocol:
        return []

    return [
        ValidationIssue(
            code="protocol_port_mismatch",
            message=(
                f"TCP/{mapping.listener.port} conventionally expects {expected.value}; "
                f"profile {profile.profile_id!r} speaks {profile.protocol.value}. "
                "Use an explicit documented override only if this deployment is intentional."
            ),
        )
    ]
