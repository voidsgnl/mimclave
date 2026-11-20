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



def test_migrate_evidence_requires_checkpoint_token_environment(
    monkeypatch, capsys
) -> None:
    monkeypatch.delenv("MIRAGE_CHECKPOINT_TOKEN", raising=False)

    result = cli.main([
        "migrate-evidence",
        "legacy.jsonl",
        "segmented",
        "--checkpoint-url",
        "https://anchor.example.test/v1/checkpoint",
        "--max-segment-bytes",
        "4096",
        "--hard-max-segment-bytes",
        "8192",
    ])

    assert result == 2
    assert "MIRAGE_CHECKPOINT_TOKEN" in capsys.readouterr().err


def test_migrate_evidence_uses_environment_token_and_reports_result(
    monkeypatch, capsys
) -> None:
    anchor = object()
    calls = {}

    class FakeStore:
        @classmethod
        def migrate_legacy_log(cls, source, destination, **kwargs):
            calls["source"] = source
            calls["destination"] = destination
            calls.update(kwargs)
            return cls()

        def verify_all(self):
            return type("Verification", (), {
                "record_count": 3,
                "head_hash": "a" * 64,
            })()

    monkeypatch.setenv("MIRAGE_CHECKPOINT_TOKEN", "test-secret")
    monkeypatch.setattr(
        cli,
        "HttpsCheckpointAnchor",
        lambda endpoint, token, *, timeout: (
            calls.update(endpoint=endpoint, token=token, timeout=timeout) or anchor
        ),
    )
    monkeypatch.setattr(cli, "SegmentedEvidenceStore", FakeStore)

    result = cli.main([
        "migrate-evidence",
        "legacy.jsonl",
        "segmented",
        "--checkpoint-url",
        "https://anchor.example.test/v1/checkpoint",
        "--max-segment-bytes",
        "4096",
        "--hard-max-segment-bytes",
        "8192",
    ])

    output = capsys.readouterr()
    assert result == 0
    assert calls["token"] == "test-secret"
    assert calls["max_segment_bytes"] == 4096
    assert calls["hard_max_segment_bytes"] == 8192
    assert "3 record(s)" in output.out
    assert "test-secret" not in output.out



def test_worker_broker_cli_requires_socket_and_evidence_paths() -> None:
    import pytest

    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["serve-worker-broker"])
    args = cli.build_parser().parse_args([
        "serve-worker-broker",
        "--socket", "var/mirage/worker/broker.sock",
        "--profile-id", "web-decoy",
        "--evidence", "var/mirage/worker-events.jsonl",
        "--allowed-uid", "1001",
        "--socket-gid", "1002",
    ])
    assert args.command == "serve-worker-broker"
    assert args.allowed_uid == [1001]
    assert args.socket_gid == 1002
