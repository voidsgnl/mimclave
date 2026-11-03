"""Deterministic HTTP decoy response generation.

This module is deliberately transport-free: it parses one bounded HTTP request
and returns a fabricated response. It never opens a socket, reads host files,
executes commands, or forwards traffic to a protected service.
"""

from dataclasses import dataclass
from html import escape

from mirage.config.models import DecoyProfile, Protocol

MAX_REQUEST_BYTES = 16 * 1024
MAX_BODY_BYTES = 8 * 1024


class RequestError(ValueError):
    """Malformed, unsupported, or oversized HTTP request."""


@dataclass(frozen=True, slots=True)
class HttpRequest:
    method: str
    target: str
    version: str
    headers: dict[str, str]

    @classmethod
    def parse(cls, raw: bytes) -> "HttpRequest":
        if len(raw) > MAX_REQUEST_BYTES:
            raise RequestError("request exceeds maximum size")
        if b"\x00" in raw:
            raise RequestError("NUL byte is not permitted")
        head, separator, body = raw.partition(b"\r\n\r\n")
        if not separator:
            raise RequestError("incomplete HTTP headers")
        if len(body) > MAX_BODY_BYTES:
            raise RequestError("request body exceeds maximum size")

        lines = head.decode("iso-8859-1").split("\r\n")
        parts = lines[0].split(" ")
        if len(parts) != 3:
            raise RequestError("malformed request line")
        method, target, version = parts
        if version not in {"HTTP/1.0", "HTTP/1.1"}:
            raise RequestError("unsupported HTTP version")
        if not method.isalpha() or not target.startswith("/") or target.startswith("//"):
            raise RequestError("invalid request method or target")
        if any(ord(char) < 0x20 for char in target):
            raise RequestError("control character in request target")

        headers: dict[str, str] = {}
        for line in lines[1:]:
            if not line or line[0] in " \t" or ":" not in line:
                raise RequestError("malformed HTTP header")
            name, value = line.split(":", 1)
            if name != name.strip():
                raise RequestError("whitespace is not permitted in HTTP header names")
            key = name.lower()
            token_chars = "!#$%&'*+-.^_`|~"
            valid_name = all(
                char.isascii() and (char.isalnum() or char in token_chars) for char in key
            )
            if not key or not valid_name:
                raise RequestError("invalid HTTP header name")
            if key in headers:
                raise RequestError(f"duplicate HTTP header: {key}")
            headers[key] = value.strip()

        if version == "HTTP/1.1" and "host" not in headers:
            raise RequestError("HTTP/1.1 requests must include Host")
        if "transfer-encoding" in headers:
            raise RequestError("transfer-encoded request bodies are not supported")
        content_length = headers.get("content-length", "0")
        if not content_length.isdigit():
            raise RequestError("invalid Content-Length")
        if int(content_length) > MAX_BODY_BYTES:
            raise RequestError("request body exceeds maximum size")
        if int(content_length) != len(body):
            raise RequestError("Content-Length does not match request body")
        if method not in {"GET", "HEAD"}:
            raise RequestError("method not supported by this decoy")
        if body:
            raise RequestError("request bodies are not accepted by this decoy")
        return cls(method, target, version, headers)


@dataclass(frozen=True, slots=True)
class HttpResponse:
    status: int
    reason: str
    headers: dict[str, str]
    body: bytes

    def to_bytes(self, method: str = "GET") -> bytes:
        headers = dict(self.headers)
        headers["Content-Length"] = str(len(self.body))
        headers["Connection"] = "close"
        status_line = f"HTTP/1.1 {self.status} {self.reason}\r\n"
        header_lines = "".join(f"{key}: {value}\r\n" for key, value in headers.items())
        payload = b"" if method == "HEAD" else self.body
        return status_line.encode("ascii") + header_lines.encode("iso-8859-1") + b"\r\n" + payload


class HttpDecoy:
    """Generate fixed fabricated pages for a configured HTTP decoy profile."""

    def __init__(self, profile: DecoyProfile) -> None:
        if profile.protocol != Protocol.HTTP:
            raise ValueError("HttpDecoy requires a profile with protocol='http'")
        if not profile.service_name.isascii() or not profile.service_version.isascii():
            raise ValueError("HTTP Server identity must contain ASCII characters only")
        self.profile = profile

    def handle(self, raw_request: bytes) -> bytes:
        request = HttpRequest.parse(raw_request)
        path = request.target.split("?", 1)[0]
        if path == "/":
            status, reason = 200, "OK"
            content_type = "text/html; charset=utf-8"
            title = self.profile.hostname
            body = (
                "<!doctype html><html><head><title>"
                + escape(title)
                + "</title></head><body><h1>"
                + escape(title)
                + "</h1><p>Welcome.</p></body></html>"
            ).encode("utf-8")
        elif path == "/robots.txt":
            status, reason = 200, "OK"
            content_type = "text/plain; charset=utf-8"
            body = b"User-agent: *\nDisallow: /private/\n"
        elif path == "/login":
            status, reason = 200, "OK"
            content_type = "text/html; charset=utf-8"
            body = (
                b"<!doctype html><html><head><title>Sign in</title></head>"
                b"<body><h1>Sign in</h1><form method=\"post\">"
                b"<input name=\"username\"><input name=\"password\" type=\"password\">"
                b"</form></body></html>"
            )
        else:
            status, reason = 404, "Not Found"
            content_type = "text/html; charset=utf-8"
            body = b"<!doctype html><html><body><h1>Not Found</h1></body></html>"

        response = HttpResponse(
            status=status,
            reason=reason,
            headers={
                "Server": f"{self.profile.service_name}/{self.profile.service_version}",
                "Content-Type": content_type,
                "X-Content-Type-Options": "nosniff",
            },
            body=body,
        )
        return response.to_bytes(request.method)
