# Changelog

All notable project changes are documented here.

## Unreleased

### Added
- Added an initial `SegmentedEvidenceStore` alongside the unchanged legacy JSONL store, with a hash-chained manifest, continuous record chain, global record numbering, anchored segment sealing, crash recovery for interrupted opening/sealing transitions, and operator-approved oldest-first retirement.
- Added segmented-store tests for automatic/manual rotation, cross-segment idempotency, checkpoint mismatch/outage, sealed-segment tampering, retirement, and interrupted-transition recovery. GitHub Actions run #208 passed 105 tests and Ruff on Python 3.12, 3.13, and 3.14. Exhaustive crash-injection coverage and target-hardware benchmarks remain outstanding.

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


### M3 — In progress
- Specified and implemented an append-only JSONL evidence store with a SHA-256 hash chain, synchronous fsync, file locking, restrictive permissions, complete-chain verification, and rejection of tampered or incomplete records.
- Added tests for concurrent appenders, tampering, incomplete records, duplicate JSON keys, symlinks, hard links, unsafe permissions, and HTTP transport integration. CI run #116 passed 73 tests and Ruff on Python 3.12, 3.13, and 3.14.


### M3 — Idempotent append
- Evidence append now uses `event_id` as an idempotency key: identical retries return the original receipt without duplicating records; reusing an ID with a different payload raises `EvidenceEventConflictError`. Existing logs containing duplicate event IDs are rejected.


### M3 — External checkpoint contract
- Added an external checkpoint interface with monotonic generations, record counts, SHA-256 head commitments, and atomic compare-and-set publication. The store can publish and verify checkpoints and detects truncated or replaced log prefixes. Only the interface is implemented; a production remote anchor adapter remains future work. CI run #135 passed 79 tests and Ruff on Python 3.12–3.14.


### M3 — Verified export
- Added a verified JSONL export operation that holds a shared source lock, verifies the complete chain and optional external checkpoint, refuses destination overwrite, writes with `0600` permissions, and fsyncs the file and destination directory. No automatic retention or deletion is performed. CI run #142 passed 82 tests and Ruff on Python 3.12–3.14.


### M3 — Performance measurement
- Added a temporary-file benchmark for synchronous append and full-chain verification throughput. CI run #151 passed the 10-event smoke test on Python 3.12–3.14. The CI sample is not a performance baseline; representative measurements must be collected on target Linux storage before optimizing or introducing asynchronous queues.


### M3 — HTTPS checkpoint client
- Added `HttpsCheckpointAnchor`, an HTTPS client adapter using verified TLS, bearer authentication, bounded responses, redirect refusal, strong ETags, and conditional create/update semantics. The external service must implement the documented atomic durable compare-and-set API; no hosted anchor server is included. CI run #169 passed 93 tests and Ruff on Python 3.12–3.14.


### M3 — Segmented evidence design (proposal)
- Added `docs/evidence-segments.md`, a design proposal for segmented log rotation and operator-approved retention: one continuous hash chain across segments, a hash-chained segment manifest, checkpoint-anchored rotation boundaries, fail-closed hard size limit, crash-recovery rules, and retirement preconditions (verified export, verified checkpoint, approval ID). The design is not implemented; no code, behaviour, or tests changed, and the existing single-file store is unaffected. Open questions are listed in the document.

### Fixed
- Corrected escaped newline artifacts in the `ROADMAP.md` handoff log and renamed the stale "M2 started" heading to "M2 delivered".
