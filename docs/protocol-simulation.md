# Protocol Simulation — M2 Design

## Objective

Provide coherent, fabricated protocol responses to clients interacting with MIRAGE-controlled decoys. Simulation must not forward requests to protected services or provide a general-purpose execution environment.

## Security boundaries

- The initial simulator is a pure request-to-response component. It does not open sockets.
- Any future listener must be opt-in and default to loopback during development.
- No production backend proxying, shell execution, host filesystem reads, or host credential access.
- Bound request/header/body sizes; reject ambiguous framing and unsupported transfer encodings.
- Do not reflect untrusted Host/header values into generated pages or response headers.
- Use fixed fabricated content and profile metadata only.
- A session must retain one coherent decoy identity; do not randomize banners or hostnames per request.
- HTTP and HTTPS are separate protocol modes. HTTPS must use TLS; a plain HTTP response on TCP/443 is not an acceptable HTTPS decoy.

## M2 implementation sequence

1. Pure HTTP response engine: parse one bounded request and return deterministic fabricated pages. No network listener. Initial implementation is underway.
2. Request/session event model: implemented as immutable `SessionEvent` records with a per-session correlation ID, strictly increasing sequence, UTC timestamp, profile ID, method/path/status, and validated source IP/port. Query strings and fragments are removed. User-Agent capture is disabled by default and can be explicitly enabled with bounded control-character sanitization. Request bodies, cookies, authorization headers, and form values are not part of the event schema.
3. Loopback-only transport adapter: optional local test server with explicit bind address, connection/time limits, and no backend forwarding.
4. TLS adapter: certificate/key handling and TLS policy; test certificates only for development, no implicit public bind.
5. Security tests: malformed request framing, oversized headers/body, duplicate headers, path traversal, host-header injection, connection exhaustion, and process shutdown.

## Initial supported behaviour

- GET / — fabricated landing page based on the decoy profile hostname.
- GET /login — static fabricated login form. This stage does not accept or store credentials.
- GET /robots.txt — fixed fabricated robots file.
- Other paths — deterministic 404.
- HEAD — same metadata and content length as GET, no response body.
- Other methods and request bodies — rejected.

## Exit criteria

- Deterministic output for identical profile and request.
- No backend forwarding or arbitrary code execution.
- Strict input bounds and unambiguous request framing.
- Identity derived only from the decoy profile, not from protected-service inventory or untrusted request headers.
- Tests pass on supported Python versions before adding a socket listener.


## Telemetry model

The event model lives in `src/mirage/telemetry/events.py`. A transport adapter is responsible for supplying peer address metadata; the model does not attempt to infer endpoint identity or inspect the remote client device. Sequence numbers define event order within one session; wall-clock timestamps are UTC observations and are not used as the sole ordering guarantee.

The default collection policy deliberately omits User-Agent and does not model request bodies or credential-bearing headers. The request target is reduced to its path before an event is created, so query parameters are not retained. This is a structured in-memory event model only: durable storage, tamper-evident chaining, retention, and export belong to M3.
