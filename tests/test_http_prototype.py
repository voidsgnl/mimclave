"""End-to-end tests for the safe local HTTP decoy prototype."""

import asyncio

import pytest

from mirage.cli import _create_http_server
from mirage.telemetry.store import JsonlEvidenceStore


HTTP_CONFIG = """version = 1

[[profiles]]
id = "local-web"
name = "Local web decoy"
protocol = "http"
service_name = "nginx"
service_version = "1.24.0"
hostname = "intranet.example.test"

[[mappings]]
profile_id = "local-web"
listener = { host = "127.0.0.1", port = 8080, transport = "tcp" }
"""


def _write_config(tmp_path, content: str = HTTP_CONFIG):
    path = tmp_path / "prototype.toml"
    path.write_text(content, encoding="utf-8")
    return path


def test_local_http_prototype_serves_and_records_request(tmp_path) -> None:
    config = _write_config(tmp_path)
    evidence = tmp_path / "state" / "events.jsonl"
    server = _create_http_server(
        config,
        profile_id="local-web",
        host="127.0.0.1",
        port=0,
        evidence_path=evidence,
    )

    async def exercise() -> bytes:
        await server.start()
        try:
            reader, writer = await asyncio.open_connection(*server.address)
            writer.write(
                b"GET /?token=must-not-be-recorded HTTP/1.1\r\n"
                b"Host: attacker.example.test\r\n\r\n"
            )
            await writer.drain()
            response = await reader.read()
            writer.close()
            await writer.wait_closed()
            return response
        finally:
            await server.close()

    response = asyncio.run(exercise())
    assert b"HTTP/1.1 200 OK" in response
    assert b"intranet.example.test" in response

    verification = JsonlEvidenceStore(evidence).verify()
    assert verification.record_count == 1
    recorded = evidence.read_text(encoding="utf-8")
    assert '"/"' in recorded
    assert "must-not-be-recorded" not in recorded
    assert "attacker.example.test" not in recorded


def test_local_http_prototype_rejects_non_loopback_host(tmp_path) -> None:
    with pytest.raises(ValueError, match="loopback"):
        _create_http_server(
            _write_config(tmp_path),
            profile_id="local-web",
            host="0.0.0.0",
            port=8080,
            evidence_path=tmp_path / "events.jsonl",
        )


def test_local_http_prototype_rejects_https_profile(tmp_path) -> None:
    https_config = HTTP_CONFIG.replace(
        'protocol = "http"', 'protocol = "https"'
    ).replace('port = 8080', 'port = 443')
    with pytest.raises(ValueError, match="HTTP profiles only"):
        _create_http_server(
            _write_config(tmp_path, https_config),
            profile_id="local-web",
            host="127.0.0.1",
            port=8080,
            evidence_path=tmp_path / "events.jsonl",
        )


def test_local_http_prototype_rejects_unmapped_profile(tmp_path) -> None:
    config = HTTP_CONFIG.replace(
        'profile_id = "local-web"', 'profile_id = "other-profile"'
    )
    with pytest.raises(ValueError, match="unknown decoy profile"):
        _create_http_server(
            _write_config(tmp_path, config),
            profile_id="local-web",
            host="127.0.0.1",
            port=8080,
            evidence_path=tmp_path / "events.jsonl",
        )
