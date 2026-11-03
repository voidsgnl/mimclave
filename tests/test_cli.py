import json

from mirage import cli
from mirage.discovery.ports import Listener


def test_discover_command_emits_json(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        cli,
        "discover_proc_listeners",
        lambda: [Listener("127.0.0.1", 8080, "tcp", "ipv4")],
    )
    assert cli.main(["discover"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload == [
        {"address": "127.0.0.1", "port": 8080, "transport": "tcp", "family": "ipv4"}
    ]


def test_validate_config_command_accepts_example(capsys) -> None:
    assert cli.main(["validate-config", "config/example.toml"]) == 0
    assert "Configuration valid" in capsys.readouterr().out


def test_validate_config_command_returns_nonzero_for_missing_file(capsys) -> None:
    assert cli.main(["validate-config", "does-not-exist.toml"]) == 2
    assert "Configuration invalid" in capsys.readouterr().err
