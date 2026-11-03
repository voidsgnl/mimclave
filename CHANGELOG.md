# Changelog

All notable project changes are documented here.

## Unreleased

### Added
- Added an opt-in asyncio HTTP transport restricted to literal loopback IPs, with bounded request reads, timeouts, connection limits, structured event emission, and explicit shutdown.
- Added transport integration tests for fragmented requests, malformed input, slow clients, connection limits, and shutdown; 57 tests pass in CI across Python 3.12–3.14.
- CI verification for structured telemetry: 51 tests and Ruff passed on Python 3.12, 3.13, and 3.14.
- Added immutable structured HTTP session events with per-session correlation IDs, sequence ordering, UTC timestamps, profile/request/response metadata, and validated source addresses.
- Added conservative telemetry defaults: query strings are removed, User-Agent capture is opt-in, and request bodies and credential-bearing headers are not represented.
- Created the initial project foundation and documented MIRAGE's purpose.
- Added immutable typed models for endpoints, decoy profiles, protected-service inventory, and listener mappings.
- Added protocol/port compatibility validation with explicit, reason-required overrides for nonstandard deployments.
- Added read-only Linux `/proc/net` discovery for TCP listeners and bound UDP sockets.
- Added unit tests for configuration validation and proc-table parsing.
- Added CI automation for supported Python versions.
- Added a versioned TOML loader, profile registry, example config, and config validation CLI.
- Added configuration schema documentation and a durable roadmap/handoff document.

### Fixed
- Corrected packaging metadata and resolved CI lint findings.

### Added
- Started M2 with a transport-free HTTP decoy engine, bounded request parser, static fabricated routes, and safety tests.
- Added protocol simulation design and security-boundary documentation.
- Hardened HTTP parsing with required HTTP/1.1 Host, strict header tokens, bounded Content-Length, and route-specific content types.
- Added path traversal, request framing, header injection, and response behaviour tests; 41 tests pass in CI across Python 3.12–3.14.

### Security
- Decoy identity strings reject control characters; HTTP simulation does not reflect untrusted Host headers, access host files, execute commands, or forward to protected services.
- Discovery performs no active network probes, shell execution, firewall changes, or traffic interception.
- Real-service inventory remains separate from decoy identity configuration.

## Security
- HTTPS decoy servers now reject TLS contexts configured below TLS 1.2. Added tests for weak TLS policy rejection and timeout closure of clients that stall before TLS negotiation.
