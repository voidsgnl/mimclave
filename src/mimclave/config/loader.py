"""TOML configuration loading for MIMCLAVE.

Loading is side-effect free: it never binds sockets, changes firewall state,
or starts decoy processes.
"""

import tomllib
from pathlib import Path
from typing import Any

from mimclave.config.models import (
    DecoyProfile,
    Endpoint,
    ListenerMapping,
    ProtectedService,
    Protocol,
)


class ConfigLoadError(ValueError):
    """Raised when a TOML document is malformed or violates the config schema."""


def _required_string(data: dict[str, Any], key: str, context: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ConfigLoadError(f"{context}.{key} must be a non-empty string")
    return value


def _endpoint(data: Any, context: str) -> Endpoint:
    if not isinstance(data, dict):
        raise ConfigLoadError(f"{context} must be a table")
    host = _required_string(data, "host", context)
    port = data.get("port")
    if not isinstance(port, int) or isinstance(port, bool):
        raise ConfigLoadError(f"{context}.port must be an integer")
    transport = data.get("transport", "tcp")
    if not isinstance(transport, str):
        raise ConfigLoadError(f"{context}.transport must be a string")
    try:
        return Endpoint(host=host, port=port, transport=transport)
    except ValueError as exc:
        raise ConfigLoadError(f"{context}: {exc}") from exc


def load_config(path: Path) -> "MimclaveConfig":
    """Load and validate the structural shape of a MIMCLAVE TOML config."""
    try:
        with path.open("rb") as stream:
            raw = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigLoadError(f"cannot read TOML config {path}: {exc}") from exc

    if raw.get("version") != 1:
        raise ConfigLoadError("top-level version must be 1")

    profiles_raw = raw.get("profiles", [])
    mappings_raw = raw.get("mappings", [])
    protected_raw = raw.get("protected_services", [])
    if not all(isinstance(value, list) for value in (profiles_raw, mappings_raw, protected_raw)):
        raise ConfigLoadError("profiles, mappings, and protected_services must be arrays of tables")

    profiles: list[DecoyProfile] = []
    for index, item in enumerate(profiles_raw):
        context = f"profiles[{index}]"
        if not isinstance(item, dict):
            raise ConfigLoadError(f"{context} must be a table")
        try:
            protocol = Protocol(_required_string(item, "protocol", context).lower())
            profiles.append(
                DecoyProfile(
                    profile_id=_required_string(item, "id", context),
                    name=_required_string(item, "name", context),
                    protocol=protocol,
                    service_name=_required_string(item, "service_name", context),
                    service_version=_required_string(item, "service_version", context),
                    hostname=_required_string(item, "hostname", context),
                )
            )
        except ValueError as exc:
            raise ConfigLoadError(f"{context}: {exc}") from exc

    mappings: list[ListenerMapping] = []
    for index, item in enumerate(mappings_raw):
        context = f"mappings[{index}]"
        if not isinstance(item, dict):
            raise ConfigLoadError(f"{context} must be a table")
        allow_override = item.get("allow_nonstandard_protocol", False)
        if not isinstance(allow_override, bool):
            raise ConfigLoadError(f"{context}.allow_nonstandard_protocol must be boolean")
        reason = item.get("override_reason")
        if reason is not None and not isinstance(reason, str):
            raise ConfigLoadError(f"{context}.override_reason must be a string")
        try:
            mappings.append(
                ListenerMapping(
                    listener=_endpoint(item.get("listener"), f"{context}.listener"),
                    profile_id=_required_string(item, "profile_id", context),
                    allow_nonstandard_protocol=allow_override,
                    override_reason=reason,
                )
            )
        except ValueError as exc:
            raise ConfigLoadError(f"{context}: {exc}") from exc

    protected: list[ProtectedService] = []
    for index, item in enumerate(protected_raw):
        context = f"protected_services[{index}]"
        if not isinstance(item, dict):
            raise ConfigLoadError(f"{context} must be a table")
        description = item.get("description", "")
        if not isinstance(description, str):
            raise ConfigLoadError(f"{context}.description must be a string")
        protected.append(
            ProtectedService(
                service_id=_required_string(item, "id", context),
                endpoint=_endpoint(item.get("endpoint"), f"{context}.endpoint"),
                description=description,
            )
        )

    return MimclaveConfig(
        profiles=tuple(profiles),
        mappings=tuple(mappings),
        protected_services=tuple(protected),
    )


from mimclave.config.registry import MimclaveConfig  # noqa: E402  (shared type, no import cycle)
