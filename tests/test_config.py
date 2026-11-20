import pytest

from mimclave.config.models import DecoyProfile, Endpoint, ListenerMapping, Protocol
from mimclave.config.validation import ConfigurationError, validate_mapping


def profile(protocol: Protocol = Protocol.HTTPS) -> DecoyProfile:
    return DecoyProfile("web-decoy", "Web decoy", protocol, "nginx", "1.24", "edge-01")


def test_endpoint_normalizes_transport() -> None:
    assert Endpoint("127.0.0.1", 443, "TCP").transport == "tcp"


@pytest.mark.parametrize("port", [0, 65536])
def test_endpoint_rejects_invalid_port(port: int) -> None:
    with pytest.raises(ValueError):
        Endpoint("127.0.0.1", port)


def test_https_profile_is_compatible_with_443() -> None:
    mapping = ListenerMapping(Endpoint("0.0.0.0", 443), "web-decoy")
    assert validate_mapping(mapping, {"web-decoy": profile()}) == []


def test_http_profile_is_rejected_on_443_by_default() -> None:
    mapping = ListenerMapping(Endpoint("0.0.0.0", 443), "web-decoy")
    issues = validate_mapping(mapping, {"web-decoy": profile(Protocol.HTTP)})
    assert [issue.code for issue in issues] == ["protocol_port_mismatch"]


def test_documented_override_allows_nonstandard_protocol() -> None:
    mapping = ListenerMapping(
        Endpoint("0.0.0.0", 443),
        "web-decoy",
        allow_nonstandard_protocol=True,
        override_reason="Legacy appliance terminates a custom protocol on this port.",
    )
    assert validate_mapping(mapping, {"web-decoy": profile(Protocol.HTTP)}) == []


def test_override_requires_reason() -> None:
    with pytest.raises(ValueError, match="override_reason"):
        ListenerMapping(
            Endpoint("0.0.0.0", 443),
            "web-decoy",
            allow_nonstandard_protocol=True,
        )


def test_unknown_profile_is_configuration_error() -> None:
    mapping = ListenerMapping(Endpoint("0.0.0.0", 443), "missing")
    with pytest.raises(ConfigurationError):
        validate_mapping(mapping, {})
