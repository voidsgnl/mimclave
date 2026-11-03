"""Typed configuration models for MIRAGE."""

from mirage.config.models import DecoyProfile, Endpoint, ListenerMapping, ProtectedService
from mirage.config.validation import ConfigurationError, validate_mapping

__all__ = [
    "ConfigurationError",
    "DecoyProfile",
    "Endpoint",
    "ListenerMapping",
    "ProtectedService",
    "validate_mapping",
]
