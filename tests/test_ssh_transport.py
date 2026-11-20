"""Security and integration tests for the loopback SSH virtual-terminal adapter."""

import asyncio
import os
import shutil

import asyncssh
import pytest

from mirage.telemetry.events import SessionEventFactory
from mirage.transport.ssh_server import SSHDecoyServer


def _host_key(tmp_path):
    path = tmp_path / "mirage-test-host-key"
    key = asyncssh.generate_private_key("ssh-ed25519")
    path.write_bytes(key.export_private_key())
    os.chmod(path, 0o600)
    return path


def test_terminal_event_records_command_name_without_arguments() -> None:
    factory = SessionEventFactory("ssh-test")
    event = factory.record_terminal_command(
        command_name="cat",
        source_ip="127.0.0.1",
        source_port=54321,
    )
    assert event.event_type == "ssh.command"
    assert event.method == "SSH"
    assert event.path == "/terminal/cat"
    assert event.source_ip == "127.0.0.1"
    assert event.source_port == 54321
    assert not hasattr(event, "command")
    assert not hasattr(event, "password")


def test_ssh_listener_rejects_non_loopback_and_unsafe_host_keys(tmp_path) -> None:
    key_path = _host_key(tmp_path)
    with pytest.raises(ValueError, match="loopback"):
        SSHDecoyServer(event_sink=lambda _event: None, host_key=key_path, host="0.0.0.0")

    os.chmod(key_path, 0o644)
    with pytest.raises(ValueError, match="permissions"):
        SSHDecoyServer(event_sink=lambda _event: None, host_key=key_path)


def test_ssh_exec_uses_virtual_terminal_and_persists_redacted_event(tmp_path) -> None:
    async def scenario() -> None:
        key_path = _host_key(tmp_path)
        events = []
        server = SSHDecoyServer(
            event_sink=events.append,
            host_key=key_path,
            port=0,
        )
        await server.start()
        host, port = server.address
        try:
            async with asyncssh.connect(
                host,
                port,
                username="untrusted-client-name",
                known_hosts=None,
                client_keys=[],
                agent_path=None,
            ) as connection:
                result = await connection.run("cat /etc/passwd", check=True, timeout=5)
            assert "www-data" in result.stdout
            assert events
            assert events[0].event_type == "ssh.command"
            assert events[0].path == "/terminal/cat"
            assert not hasattr(events[0], "password")
        finally:
            await server.close()

    asyncio.run(scenario())


def test_ssh_interactive_sessions_have_separate_virtual_directories(tmp_path) -> None:
    ssh = shutil.which("ssh")
    if ssh is None:
        pytest.skip("OpenSSH client is not installed")

    async def scenario() -> None:
        key_path = _host_key(tmp_path)
        events = []
        server = SSHDecoyServer(
            event_sink=events.append,
            host_key=key_path,
            port=0,
        )
        await server.start()
        host, port = server.address
        try:
            client = await asyncio.create_subprocess_exec(
                ssh,
                "-tt",
                "-p",
                str(port),
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                "BatchMode=yes",
                "-o",
                "PreferredAuthentications=none",
                f"visitor@{host}",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                client.communicate(b"cd /home/deploy\\npwd\\nexit\\n"),
                timeout=10,
            )
            assert client.returncode == 0, stderr.decode(errors="replace")
            output = stdout.decode(errors="replace")
            assert "/home/deploy" in output
            assert [event.path for event in events] == [
                "/terminal/cd",
                "/terminal/pwd",
            ]
        finally:
            await server.close()

    asyncio.run(scenario())


def test_ssh_evidence_failure_sends_no_command_output(tmp_path) -> None:
    async def scenario() -> None:
        key_path = _host_key(tmp_path)

        def broken_sink(_event) -> None:
            raise RuntimeError("simulated evidence failure")

        server = SSHDecoyServer(
            event_sink=broken_sink,
            host_key=key_path,
            port=0,
        )
        await server.start()
        host, port = server.address
        try:
            async with asyncssh.connect(
                host,
                port,
                username="visitor",
                known_hosts=None,
                client_keys=[],
                agent_path=None,
            ) as connection:
                result = await connection.run("whoami", check=False, timeout=5)
            assert result.stdout == ""
            assert result.exit_status == 1
        finally:
            await server.close()

    asyncio.run(scenario())
