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
