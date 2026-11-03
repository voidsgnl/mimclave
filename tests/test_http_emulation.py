import pytest

from mirage.config.models import DecoyProfile, Protocol
from mirage.emulation.http import HttpDecoy, RequestError


@pytest.fixture
def decoy() -> HttpDecoy:
    profile = DecoyProfile(
        profile_id="web",
        name="Web decoy",
        protocol=Protocol.HTTP,
        service_name="nginx",
        service_version="1.24.0",
        hostname="portal.example.test",
    )
    return HttpDecoy(profile)


def test_root_response_uses_fabricated_profile_identity(decoy: HttpDecoy) -> None:
    response = decoy.handle(b"GET / HTTP/1.1\r\nHost: attacker.test\r\n\r\n")
    assert response.startswith(b"HTTP/1.1 200 OK\r\n")
    assert b"Server: nginx/1.24.0" in response
    assert b"portal.example.test" in response
    assert b"attacker.test" not in response


def test_unknown_route_returns_404(decoy: HttpDecoy) -> None:
    response = decoy.handle(b"GET /missing HTTP/1.1\r\nHost: example.test\r\n\r\n")
    assert response.startswith(b"HTTP/1.1 404 Not Found")


def test_head_response_has_no_body_but_correct_content_length(decoy: HttpDecoy) -> None:
    response = decoy.handle(b"HEAD / HTTP/1.1\r\nHost: example.test\r\n\r\n")
    head, body = response.split(b"\r\n\r\n", 1)
    assert b"Content-Length:" in head
    assert body == b""


@pytest.mark.parametrize(
    "raw",
    [
        b"GET / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n",
        b"POST /login HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n",
        b"GET //evil.test HTTP/1.1\r\nHost: x\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: x\r\nHost: y\r\n\r\n",
    ],
)
def test_reject_unsupported_or_ambiguous_requests(decoy: HttpDecoy, raw: bytes) -> None:
    with pytest.raises(RequestError):
        decoy.handle(raw)


def test_request_size_is_bounded(decoy: HttpDecoy) -> None:
    with pytest.raises(RequestError, match="maximum size"):
        decoy.handle(b"GET / HTTP/1.1\r\nX: " + b"a" * 17000 + b"\r\n\r\n")


def test_http_decoy_rejects_non_http_protocol_profile() -> None:
    profile = DecoyProfile("ftp", "FTP", Protocol.FTP, "vsftpd", "3.0", "host")
    with pytest.raises(ValueError, match="http or https"):
        HttpDecoy(profile)


def test_path_traversal_is_not_resolved_to_host_files(decoy: HttpDecoy) -> None:
    response = decoy.handle(
        b"GET /../../etc/passwd HTTP/1.1\r\nHost: example.test\r\n\r\n"
    )
    assert response.startswith(b"HTTP/1.1 404 Not Found")
    assert b"root:" not in response


def test_profile_rejects_header_injection() -> None:
    with pytest.raises(ValueError, match="control characters"):
        DecoyProfile("bad", "Bad", Protocol.HTTP, "nginx", "1.2\r\nX-Evil: yes", "host")


@pytest.mark.parametrize(
    "raw",
    [
        b"GET / HTTP/1.1\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost : example.test\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: x\r\nContent-Length: 999999999\r\n\r\n",
    ],
)
def test_reject_missing_host_bad_header_and_oversized_body(decoy: HttpDecoy, raw: bytes) -> None:
    with pytest.raises(RequestError):
        decoy.handle(raw)


def test_http_decoy_rejects_non_ascii_server_header() -> None:
    profile = DecoyProfile("web", "Web", Protocol.HTTP, "ngïnx", "1.2", "host")
    with pytest.raises(ValueError, match="ASCII"):
        HttpDecoy(profile)

def test_robots_route_uses_plain_text_content_type(decoy: HttpDecoy) -> None:
    response = decoy.handle(
        b"GET /robots.txt HTTP/1.1\r\nHost: example.test\r\n\r\n"
    )
    assert b"Content-Type: text/plain; charset=utf-8" in response
