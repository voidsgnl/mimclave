from pathlib import Path

import pytest

from mimclave.config.loader import ConfigLoadError, load_config
from mimclave.config.registry import ProfileRegistry

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
    path = tmp_path / "mimclave.toml"
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

def test_registry_rejects_duplicate_profile_ids(tmp_path: Path) -> None:
    duplicated = VALID_CONFIG + """
[[profiles]]
id = "web-front"
name = "Duplicate profile"
protocol = "https"
service_name = "nginx"
service_version = "1.24"
hostname = "duplicate.example.test"
"""
    config = load_config(write_config(tmp_path, duplicated))
    with pytest.raises(ValueError, match="duplicate decoy profile"):
        ProfileRegistry(config)


def test_registry_rejects_duplicate_protected_service_ids(tmp_path: Path) -> None:
    duplicated = VALID_CONFIG + """
[[protected_services]]
id = "real-app"
endpoint = { host = "127.0.0.1", port = 9001 }
"""
    registry = ProfileRegistry(load_config(write_config(tmp_path, duplicated)))
    with pytest.raises(ValueError, match="duplicate protected service id"):
        registry.validate()


def test_override_requires_a_reason_in_toml(tmp_path: Path) -> None:
    invalid = VALID_CONFIG.replace(
        'listener = { host = "0.0.0.0", port = 443, transport = "tcp" }',
        'listener = { host = "0.0.0.0", port = 443, transport = "tcp" }\n'
        'allow_nonstandard_protocol = true',
    ).replace('protocol = "https"', 'protocol = "http"')
    with pytest.raises(ConfigLoadError, match="override_reason"):
        load_config(write_config(tmp_path, invalid))


def test_udp_mapping_does_not_apply_tcp_port_conventions(tmp_path: Path) -> None:
    udp_config = VALID_CONFIG.replace(
        'listener = { host = "0.0.0.0", port = 443, transport = "tcp" }',
        'listener = { host = "0.0.0.0", port = 443, transport = "udp" }',
    ).replace('protocol = "https"', 'protocol = "custom"')
    registry = ProfileRegistry(load_config(write_config(tmp_path, udp_config)))
    assert registry.validate().issues == ()


def test_reject_malformed_toml(tmp_path: Path) -> None:
    with pytest.raises(ConfigLoadError, match="cannot read TOML"):
        load_config(write_config(tmp_path, 'version = "unterminated'))
