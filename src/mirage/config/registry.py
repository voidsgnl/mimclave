"""Validated in-memory registry for MIRAGE configuration."""

from dataclasses import dataclass

from mirage.config.models import DecoyProfile, ListenerMapping, ProtectedService
from mirage.config.validation import ConfigurationError, ValidationIssue, validate_mapping


@dataclass(frozen=True, slots=True)
class MirageConfig:
    profiles: tuple[DecoyProfile, ...]
    mappings: tuple[ListenerMapping, ...]
    protected_services: tuple[ProtectedService, ...] = ()


@dataclass(frozen=True, slots=True)
class RegistryValidation:
    issues: tuple[ValidationIssue, ...]


class ProfileRegistry:
    """Resolve listener mappings against independent decoy profile identities."""

    def __init__(self, config: MirageConfig) -> None:
        self._config = config
        self._profiles: dict[str, DecoyProfile] = {}
        for profile in config.profiles:
            if profile.profile_id in self._profiles:
                raise ConfigurationError(f"duplicate decoy profile id: {profile.profile_id}")
            self._profiles[profile.profile_id] = profile

    @property
    def profiles(self) -> dict[str, DecoyProfile]:
        return dict(self._profiles)

    def resolve(self, mapping: ListenerMapping) -> DecoyProfile:
        profile = self._profiles.get(mapping.profile_id)
        if profile is None:
            raise ConfigurationError(f"unknown decoy profile: {mapping.profile_id}")
        return profile

    def validate(self) -> RegistryValidation:
        issues: list[ValidationIssue] = []
        seen_listeners: set[tuple[str, int, str]] = set()
        seen_services: set[str] = set()

        for service in self._config.protected_services:
            if service.service_id in seen_services:
                raise ConfigurationError(f"duplicate protected service id: {service.service_id}")
            seen_services.add(service.service_id)

        for mapping in self._config.mappings:
            key = (mapping.listener.host, mapping.listener.port, mapping.listener.transport)
            if key in seen_listeners:
                raise ConfigurationError(
                    f"multiple decoy mappings target {mapping.listener.transport}://"
                    f"{mapping.listener.host}:{mapping.listener.port}"
                )
            seen_listeners.add(key)
            self.resolve(mapping)
            issues.extend(validate_mapping(mapping, self._profiles))
        return RegistryValidation(tuple(issues))
