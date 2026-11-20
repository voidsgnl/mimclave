"""Security and integration tests for the loopback SSH virtual-terminal adapter."""

import asyncio
import os

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
                username="visitor",
                known_hosts=None,
                client_keys=[],
                agent_path=None,
            ) as connection:
                first = await connection.create_process(term_type="xterm")
                await asyncio.wait_for(first.stdout.readuntil("$ "), timeout=5)
                first.stdin.write("cd /home/deploy\\n")
                await first.stdin.drain()
                first_prompt = await asyncio.wait_for(first.stdout.readuntil("$ "), timeout=5)
                assert "/home/deploy$ " in first_prompt

                second = await connection.create_process(term_type="xterm")
                await asyncio.wait_for(second.stdout.readuntil("$ "), timeout=5)
                second.stdin.write("pwd\\n")
                await second.stdin.drain()
                second_output = await asyncio.wait_for(second.stdout.readuntil("$ "), timeout=5)
                assert "/var/www" in second_output

                first.stdin.write("exit\\n")
                second.stdin.write("exit\\n")
                await first.stdin.drain()
                await second.stdin.drain()
                await asyncio.wait_for(first.wait_closed(), timeout=5)
                await asyncio.wait_for(second.wait_closed(), timeout=5)
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
