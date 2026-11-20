from datetime import UTC, datetime, timedelta, timezone

import pytest

from mimclave.telemetry.events import SessionEvent, SessionEventFactory


def test_event_factory_assigns_correlation_and_monotonic_sequence() -> None:
    factory = SessionEventFactory("web-prod-decoy", session_id="session-1")
    first = factory.record_http_request(method="get", target="/?token=secret", status_code=200)
    second = factory.record_http_request(method="HEAD", target="/login", status_code=200)

    assert first.session_id == second.session_id == "session-1"
    assert first.profile_id == second.profile_id == "web-prod-decoy"
    assert first.sequence == 1
    assert second.sequence == 2
    assert first.event_id != second.event_id
    assert first.path == "/"
    assert "secret" not in repr(first)
    assert first.user_agent is None


def test_event_factory_records_only_explicitly_enabled_user_agent() -> None:
    default = SessionEventFactory("web").record_http_request(
        method="GET", target="/", status_code=200, user_agent="Example/1.0"
    )
    enabled = SessionEventFactory("web", capture_user_agent=True).record_http_request(
        method="GET", target="/", status_code=200, user_agent="Example/1.0\r\nInjected"
    )

    assert default.user_agent is None
    assert enabled.user_agent == "Example/1.0  Injected"


def test_source_address_is_validated_and_normalized() -> None:
    event = SessionEventFactory("web").record_http_request(
        method="GET", target="/", status_code=200, source_ip="2001:0db8::1", source_port=44321
    )
    assert event.source_ip == "2001:db8::1"
    assert event.source_port == 44321

    with pytest.raises(ValueError, match="valid IP"):
        SessionEventFactory("web").record_http_request(
            method="GET", target="/", status_code=200, source_ip="not-an-ip"
        )


@pytest.mark.parametrize("target", ["https://example.com/", "//example.com/", ""])
def test_factory_rejects_non_origin_form_targets(target: str) -> None:
    with pytest.raises(ValueError):
        SessionEventFactory("web").record_http_request(
            method="GET", target=target, status_code=200
        )


def test_event_requires_utc_timestamp() -> None:
    with pytest.raises(ValueError, match="UTC"):
        SessionEvent(
            event_id="event", session_id="session", sequence=1,
            occurred_at=datetime(2026, 1, 1, tzinfo=timezone(timedelta(hours=2))),
            profile_id="web", event_type="http.request", method="GET",
            path="/", status_code=200,
        )


def test_event_rejects_invalid_sequence_status_and_source_port() -> None:
    factory = SessionEventFactory("web")
    with pytest.raises(ValueError, match="status_code"):
        factory.record_http_request(method="GET", target="/", status_code=99)
    with pytest.raises(ValueError, match="source_port"):
        factory.record_http_request(
            method="GET", target="/", status_code=200, source_port=70000
        )


def test_clock_must_return_utc_datetime() -> None:
    factory = SessionEventFactory(
        "web", clock=lambda: datetime(2026, 1, 1, tzinfo=timezone(timedelta(hours=1)))
    )
    with pytest.raises(ValueError, match="UTC"):
        factory.record_http_request(method="GET", target="/", status_code=200)


def test_factory_uses_injected_utc_clock() -> None:
    now = datetime(2026, 11, 3, 10, 0, tzinfo=UTC)
    factory = SessionEventFactory("web", clock=lambda: now)
    event = factory.record_http_request(method="GET", target="/", status_code=200)
    assert event.occurred_at == now
