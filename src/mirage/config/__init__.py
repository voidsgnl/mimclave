"""Typed configuration models and validation for MIRAGE."""

from mirage.config.loader import ConfigLoadError, load_config
from mirage.config.models import DecoyProfile, Endpoint, ListenerMapping, ProtectedService, Protocol
from mirage.config.registry import MirageConfig, ProfileRegistry
from mirage.config.validation import ConfigurationError, validate_mapping

__all__ = [
    "ConfigLoadError",
    "ConfigurationError",
    "DecoyProfile",
    "Endpoint",
    "ListenerMapping",
    "MirageConfig",
    "ProfileRegistry",
    "ProtectedService",
    "Protocol",
    "load_config",
    "validate_mapping",
]
