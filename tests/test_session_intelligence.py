"""Tests for evidence-backed MIRAGE activity analysis."""

from datetime import UTC, datetime, timedelta

import pytest

from mirage import cli
from mirage.telemetry.events import SessionEventFactory
from mirage.telemetry.intelligence import build_activity_report
from mirage.telemetry.store import EvidenceIntegrityError, JsonlEvidenceStore


BASE = datetime(2026, 11, 20, 10, 0, tzinfo=UTC)


def event(
    index: int,
    path: str,
    *,
    seconds: int = 0,
    source_ip: str | None = "127.0.0.1",
    status: int = 404,
) -> dict:
    return {
        "event_id": f"event-{index:04d}",
        "session_id": f"session-{index:04d}",
        "sequence": 1,
        "occurred_at": (BASE + timedelta(seconds=seconds)).isoformat(),
        "profile_id": "local-web",
        "event_type": "http.request",
        "method": "GET",
        "path": path,
        "status_code": status,
        "source_ip": source_ip,
        "source_port": 40000 + index,
        "user_agent": None,
    }


def test_activity_report_groups_source_profile_and_idle_window() -> None:
    report = build_activity_report(
        [
            event(1, "/", seconds=0, status=200),
            event(2, "/login", seconds=10, status=200),
            event(3, "/", seconds=4000, status=200),
            event(4, "/other", seconds=4010, source_ip="192.0.2.8"),
        ],
        idle_timeout_seconds=1800,
    )

    assert report["evidence_records"] == 4
    assert report["activity_clusters"] == 3
    assert report["clusters"][0]["request_count"] == 2
    assert report["clusters"][1]["source_ip"] == "127.0.0.1"
    assert report["clusters"][2]["source_ip"] == "192.0.2.8"
    assert "not authenticated sessions" in report["interpretation"]


def test_activity_report_flags_path_sweep_sensitive_path_and_rate() -> None:
    paths = ["/.env", "/admin", "/private-a", "/private-b", "/private-c"]
    events = [
        event(index, path, seconds=index)
        for index, path in enumerate(paths, start=1)
    ]
    events.extend(
        event(index, "/admin", seconds=index)
        for index in range(6, 11)
    )

    report = build_activity_report(events)
    codes = {item["code"] for item in report["clusters"][0]["indicators"]}

    assert codes == {
        "sensitive-path-probe",
        "not-found-sweep",
        "repeated-path",
        "high-request-rate",
    }


def test_activity_report_does_not_group_unknown_sources() -> None:
    report = build_activity_report([
        event(1, "/", source_ip=None),
        event(2, "/login", seconds=1, source_ip=None),
    ])

    assert report["activity_clusters"] == 2


def test_activity_report_rejects_invalid_idle_timeout() -> None:
    with pytest.raises(ValueError, match="at least 1"):
        build_activity_report([], idle_timeout_seconds=0)


def test_evidence_store_reads_only_verified_event_payloads(tmp_path) -> None:
    path = tmp_path / "events.jsonl"
    store = JsonlEvidenceStore(path)
    factory = SessionEventFactory(
        "local-web", clock=lambda: datetime(2026, 11, 20, tzinfo=UTC)
    )
    store.append(factory.record_http_request(
        method="GET",
        target="/login?secret=not-recorded",
        status_code=200,
        source_ip="127.0.0.1",
    ))

    events = store.read_events()
    assert len(events) == 1
    assert events[0]["path"] == "/login"
    assert "secret" not in str(events[0])

    path.write_text(path.read_text(encoding="utf-8").replace("/login", "/admin"))
    with pytest.raises(EvidenceIntegrityError):
        store.read_events()


def test_inspect_sessions_cli_emits_json_from_verified_evidence(tmp_path, capsys) -> None:
    path = tmp_path / "events.jsonl"
    store = JsonlEvidenceStore(path)
    factory = SessionEventFactory(
        "local-web", clock=lambda: datetime(2026, 11, 20, tzinfo=UTC)
    )
    store.append(factory.record_http_request(
        method="GET", target="/", status_code=200, source_ip="127.0.0.1"
    ))

    assert cli.main(["inspect-sessions", str(path), "--json"]) == 0
    output = capsys.readouterr().out
    assert '"activity_clusters": 1' in output
    assert '"path": "/"' in output


def test_inspect_sessions_cli_refuses_tampered_evidence(tmp_path, capsys) -> None:
    path = tmp_path / "events.jsonl"
    store = JsonlEvidenceStore(path)
    factory = SessionEventFactory(
        "local-web", clock=lambda: datetime(2026, 11, 20, tzinfo=UTC)
    )
    store.append(factory.record_http_request(
        method="GET", target="/", status_code=200, source_ip="127.0.0.1"
    ))
    tampered = path.read_text(encoding="utf-8").replace(
        '"status_code":200', '"status_code":404'
    )
    path.write_text(tampered, encoding="utf-8")

    assert cli.main(["inspect-sessions", str(path)]) == 2
    assert "Session inspection failed" in capsys.readouterr().err
