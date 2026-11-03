from pathlib import Path

import pytest

from mirage.config.loader import ConfigLoadError, load_config
from mirage.config.registry import ProfileRegistry

VALID_CONFIG = """
version = 1

[[profiles]]
id = "web-front"
name = "Public web decoy"
protocol = "https"
service_name = "nginx"
service_version = "1.24.0"
hostname = "portal.example.test"

[[mappings]]
profile_id = "web-front"
listener = { host = "0.0.0.0", port = 443, transport = "tcp" }

[[protected_services]]
id = "real-app"
description = "Internal application; not copied into decoy identity."
endpoint = { host = "127.0.0.1", port = 9000, transport = "tcp" }
"""


def write_config(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "mirage.toml"
    path.write_text(content, encoding="utf-8")
    return path


def test_load_config_and_validate_registry(tmp_path: Path) -> None:
    config = load_config(write_config(tmp_path, VALID_CONFIG))
    registry = ProfileRegistry(config)
    assert registry.resolve(config.mappings[0]).hostname == "portal.example.test"
    assert registry.validate().issues == ()
    assert config.protected_services[0].endpoint.port == 9000


def test_reject_unknown_config_version(tmp_path: Path) -> None:
    with pytest.raises(ConfigLoadError, match="version"):
        load_config(write_config(tmp_path, "version = 2"))


def test_reject_unknown_protocol(tmp_path: Path) -> None:
    invalid = VALID_CONFIG.replace('protocol = "https"', 'protocol = "telnet"')
    with pytest.raises(ConfigLoadError, match="telnet"):
        load_config(write_config(tmp_path, invalid))


def test_registry_rejects_duplicate_listener_mapping(tmp_path: Path) -> None:
    duplicated = VALID_CONFIG + """
[[mappings]]
profile_id = "web-front"
listener = { host = "0.0.0.0", port = 443, transport = "tcp" }
"""
    registry = ProfileRegistry(load_config(write_config(tmp_path, duplicated)))
    with pytest.raises(ValueError, match="multiple decoy mappings"):
        registry.validate()


def test_registry_rejects_unknown_profile(tmp_path: Path) -> None:
    invalid = VALID_CONFIG.replace('profile_id = "web-front"', 'profile_id = "missing"')
    registry = ProfileRegistry(load_config(write_config(tmp_path, invalid)))
    with pytest.raises(ValueError, match="unknown decoy profile"):
        registry.validate()


def test_registry_rejects_protocol_port_mismatch(tmp_path: Path) -> None:
    invalid = VALID_CONFIG.replace('protocol = "https"', 'protocol = "http"')
    registry = ProfileRegistry(load_config(write_config(tmp_path, invalid)))
    assert registry.validate().issues[0].code == "protocol_port_mismatch"
