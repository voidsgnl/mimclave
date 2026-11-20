# Changelog

All notable project changes are documented here.

## Unreleased

### Security
- Added a separate private supervisor-control socket and bounded registration codec. Registrations bind a session UUID to protocol, source IP/port, and the expected worker UID/PID; the broker checks Linux `SO_PEERCRED`, rejects unregistered or mismatched workers, prevents a registration from being claimed twice, and uses only supervisor-supplied source metadata in evidence. Registration is a supervisor API foundation: HTTP/SSH handlers are not yet wired to it, and a same-UID development configuration is not a security boundary. Tests added; CI verification pending.

### Added
- Added a Linux Unix-domain-socket worker evidence broker and `mirage serve-worker-broker` CLI. The broker uses SO_PEERCRED UID allowlisting, private socket/directory checks, bounded client and message handling, one session per connection, monotonic sequence validation, recent session-replay rejection, bounded idle timeouts, orderly shutdown, broker-owned profile identity and receipt timestamps, and broker-only writes to the existing hash-chained evidence store. Worker-claimed source addresses are not persisted before trusted supervisor registration. Optional group-scoped socket access requires explicit worker UIDs and a constrained parent-directory mode. Tests cover accepted and rejected events, peer credentials, sequence handling, socket replacement safety, group access, replay rejection, trusted metadata handling, and orderly shutdown. GitHub Actions run #417 passed 282 tests, the evidence benchmark smoke test, and Ruff on Python 3.12–3.14. The current protocol transports are not yet wired to this broker, and this is not an OS sandbox.

### Added
- Added a bounded worker-to-supervisor event IPC contract with strict newline-delimited JSON framing, duplicate/unknown-field rejection, size limits, timestamp/IP/metadata validation, and per-session monotonic sequence enforcement. The codec does not open sockets or grant evidence-file access; a transport and broker process are still future work. GitHub Actions run #377 passed 265 tests, benchmark smoke test, and Ruff on Python 3.12–3.14.
- Added declarative sandbox policy types for simulation, isolated-worker, and disposable-VM tiers, with bounded resource limits and validation of namespaces, seccomp policy names, privilege restrictions, host-mount/credential prohibitions, and network modes. This is policy modelling only; no namespace, cgroup, seccomp, VM, or traffic-enforcement mechanism is executed yet. Automated tests added; CI verification pending.

### Added
- Added an experimental loopback-only SSH adapter using optional AsyncSSH. Each channel receives a separate in-memory virtual terminal; connection/session counts, command length/count, input deadline, and channel window are bounded. SSH forwarding, SFTP, agent forwarding, and X11 are disabled. Interactions are durably recorded before output, with command arguments and credentials omitted. Added tests for SSH exec command execution, callback-level session isolation, loopback/key restrictions, and fail-closed evidence handling. GitHub Actions run #353 passed Python 3.12, 3.13, and 3.14, including Ruff.
- Added an initial in-memory Linux-like terminal simulator and `mirage simulate-terminal` CLI. It provides fabricated users, processes, directories, and files through a strict read-only command allowlist. Shell operators, expansions, unknown commands, and path traversal are rejected; no subprocess, host filesystem, or network access is used. The separate SSH transport is experimental and loopback-only; production isolation and public deployment remain future work. GitHub Actions run #353 passed all Python matrices.
- Added `mirage inspect-sessions` for verified evidence inspection, source/profile/idle-window activity clustering, request timelines, route/status summaries, and conservative indicators for sensitive-path probes, 404 sweeps, repeated routes, and high request rates. Request bodies, query strings, cookies, authorization headers, and User-Agent values remain excluded. Activity clusters are heuristics, not authenticated user sessions. Tests added; CI verification pending.
- Added a runnable local HTTP prototype command, `mirage serve-http`, with explicit loopback-only binding, configuration/profile validation, and durable hash-chained evidence append before a decoy response is sent. Added `mirage verify-evidence`, a dedicated loopback HTTP configuration, and end-to-end tests for request handling, query-string exclusion, evidence verification, and rejection of non-loopback/unsupported profiles. CI verification is pending.

### Added
- Added an initial `SegmentedEvidenceStore` alongside the unchanged legacy JSONL store, with a hash-chained manifest, continuous record chain, global record numbering, anchored segment sealing, crash recovery for interrupted opening/sealing transitions, and operator-approved oldest-first retirement.
- Added segmented-store tests for automatic/manual rotation, cross-segment idempotency, checkpoint mismatch/outage and prefix edge cases, sealed-segment tampering, retirement, manifest tampering/truncation, and missing/unmanifested segment files. Crash injection now covers initialization, manifest and segment fsync boundaries, durable append before receipt delivery, partial append failure, rotation successor creation, retirement, and migration publication before/after rename. Partial records are not silently truncated; recovery fails closed. GitHub Actions run #238 passed 130 tests, the evidence benchmark smoke test, and Ruff on Python 3.12, 3.13, and 3.14. Exhaustive filesystem-boundary coverage and target-hardware benchmarks remain outstanding.
- Added non-destructive legacy JSONL migration: verify the source, anchor its complete head, copy its original record bytes unchanged into sealed segment 1, create the active successor, verify the staged store, and atomically publish the destination. Publication uses Linux `renameat2(RENAME_NOREPLACE)` to prevent overwriting an existing or racing destination; migration rejects source logs larger than the configured hard segment limit. Tests cover byte-for-byte preservation, source retention, tampering, checkpoint conflicts, destination races, and oversized input. GitHub Actions run #251 passed 132 tests and Ruff on Python 3.12, 3.13, and 3.14.
- Expanded `scripts/benchmark_evidence_store.py` to compare legacy JSONL and segmented append/verification, report segment count and storage bytes, and accept an explicit segment size. The segmented benchmark uses a clearly labelled in-memory anchor; CI run #245 exercises automatic rotation with a 1024-byte segment size. Target-hardware measurements remain outstanding.
- Added the `mirage migrate-evidence` operator command. It reads the HTTPS checkpoint bearer token from an environment variable, not command-line arguments, and reports the verified migrated head. Added CLI tests for missing-token handling and secret-safe execution. GitHub Actions run #257 passed 134 tests and Ruff on Python 3.12–3.14.

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


### M3 — Independent checkpoint service implementation
- Added a SQLite-backed checkpoint service with authenticated conditional GET/PUT, strong ETags, monotonic compare-and-set, FULL synchronous commits, private file permissions, loopback-only binding, and an append-only hash-chained checkpoint history. Added request-size/type/authentication checks, request timeouts, token-strength enforcement, and systemd/Caddy deployment examples. The service is a reference implementation only and has not been deployed or independently audited. GitHub Actions run #277 passed 146 tests and Ruff on Python 3.12–3.14.


## Unreleased — 2026-11-20

### Added
- Added a private supervisor-control Unix socket for registering worker sessions before evidence events are accepted.
- Bound each registration to the expected worker UID/PID, protocol, and supervisor-supplied client peer address/port; worker events are checked against kernel `SO_PEERCRED`.
- Added registration expiry, replay rejection, bounded pending registrations, and control-socket lifecycle handling.
- Added tests for unregistered workers, UID/PID mismatch, protocol mismatch, and trusted source metadata.

### Security notes
- The default same-UID development mode is not an isolation boundary. Use a dedicated worker UID and explicit allowlist.
- The registration/evidence broker is not yet connected to HTTP/SSH transports and does not provide OS sandboxing or traffic steering.
- CI verification for this change is pending.
