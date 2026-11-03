# MIRAGE Roadmap & Handoff

> **Purpose:** Durable project handoff. Update this file whenever implementation progress, decisions, blockers, or the next task changes. A new chat should resume from this file without relying on conversation history.

## Project identity
- Product: Linux-first defensive cyber-deception platform.
- Repository: https://github.com/voidsgnl/mirage
- Working branch: `main`; do not create branches unless explicitly requested.
- Python: 3.12+; primary host target: Ubuntu/Linux.

## Non-negotiable decisions
- Configure real protected services and decoy identities independently; never copy backend identity into a decoy automatically.
- Default protocol/port expectations apply (e.g. HTTPS/TLS on TCP 443). Nonstandard mappings require an explicit reason.
- Decoy identity must remain coherent during a session.
- A decoy compromise must not expose host resources, production services, credentials, data, or internal networks.
- Enforcement must fail closed independently of the MIRAGE process.
- Default-deny sandbox egress; no host credentials or unrestricted host mounts.
- Begin with read-only discovery and protocol simulation, not arbitrary shell execution.
- MIRAGE observes interactions with its own decoys; it cannot inspect arbitrary commands/files on an attacker's device.
- Defensive use only on owned/authorized systems. No retaliation. Attribution is probabilistic, not identity proof.

## Status — 2026-11-03
**M0 — project foundation: complete.**  
**M1 — configuration and read-only discovery: COMPLETE.**  
**M2 — safe protocol simulation: pure HTTP engine, structured session-event model, loopback-only HTTP/HTTPS transports, and TLS 1.2 minimum policy implemented and CI-verified on Python 3.12–3.14.**
**M3 — telemetry and evidence: initial append-only, hash-chained JSONL evidence store implemented and CI-verified (73 tests and Ruff on Python 3.12–3.14).**

### M1 delivered
- [x] Architecture, requirements, threat-model, and configuration-schema documents.
- [x] Immutable endpoint, decoy profile, protected-service, and listener-mapping models.
- [x] Versioned TOML loader with structural validation and actionable parse errors.
- [x] Profile registry with unique profile IDs, mapping resolution, duplicate listener and protected-service checks.
- [x] Protocol/port compatibility checks; deliberate mismatches require an explicit reason.
- [x] TCP conventions are not incorrectly applied to UDP mappings.
- [x] Example TOML config keeps real protected-service inventory separate from decoy identity.
- [x] Read-only Linux /proc/net discovery for TCP listeners and bound UDP sockets.
- [x] mirage discover and python -m mirage discover CLI.
- [x] mirage validate-config <path> CLI with distinct exit codes for valid, policy-invalid, and load-invalid configurations.
- [x] GitHub Actions matrix for Python 3.12, 3.13, and 3.14.
- [x] Package installation, 25 tests, and Ruff checks passed on all three Python versions.

### M2 started
- [x] Pure, transport-free HTTP request parser and deterministic fabricated response generator.
- [x] Bounded request sizes; reject unsupported methods, request bodies, transfer-encoding, duplicate headers, malformed framing, and ambiguous targets.
- [x] Static routes for /, /login, /robots.txt; deterministic 404 for other paths.
- [x] Decoy identity comes from profile data only; Host header is not reflected.
- [x] Decoy identity fields reject control characters to prevent response-header injection.
- [x] CI verified the HTTP engine and parser safety tests on Python 3.12, 3.13, and 3.14.
- [x] Add immutable structured HTTP session events with per-session correlation IDs and strictly increasing sequence numbers.
- [x] Record UTC timestamps, profile ID, method, path, response status, and optional source IP/port.
- [x] Strip query strings and fragments; request bodies, cookies, authorization headers, and form values are outside the event schema.
- [x] Keep User-Agent capture disabled by default; optional capture is bounded and control-character sanitized.
- [x] Verify event model and tests in CI across Python 3.12–3.14 (run #57: 51 tests passed and Ruff passed on all three versions).
- [x] Add an opt-in HTTP transport adapter restricted to literal loopback IP addresses; non-loopback and hostname binds are rejected.
- [x] Bound request header reads to the HTTP parser limit and apply per-request timeouts and a maximum active-connection count.
- [x] Emit structured session events before sending responses; telemetry callback failure does not send the decoy response.
- [x] Close active clients during explicit, idempotent shutdown; no backend forwarding or keep-alive.
- [x] Add oversized-header rejection and telemetry-sink-failure tests; a telemetry failure closes the connection without returning an unrecorded decoy response (CI run #76: 59 tests passed and Ruff passed on Python 3.12–3.14).
- [x] Add explicit HTTPS/TLS transport requiring caller-provided server-side `ssl.SSLContext`; no automatic certificate generation or implicit trust.
- [x] Keep HTTPS transport restricted to literal loopback IP addresses and bound TLS handshake time.
- [x] Verify TLS handshake, trusted certificate validation, untrusted certificate rejection, and transport tests in CI across Python 3.12–3.14 (run #89; 62 tests and Ruff passed).
- [x] Require TLS 1.2 or newer in caller-provided server contexts; reject weaker TLS policy.
- [x] Test that incomplete TLS handshakes close at the configured timeout without producing HTTP events (run #99; 63 tests and Ruff passed across Python 3.12–3.14).

## CI verification record
- GitHub Actions run #116, commit `9125a26`: **success** on Python 3.12, 3.13, and 3.14. 73 tests passed; Ruff passed in all matrix jobs (initial M3 JSONL evidence store and transport integration).
- GitHub Actions run #116, commit `9125a26`: **success** on Python 3.12, 3.13, and 3.14. 73 tests passed; Ruff passed in all matrix jobs (initial M3 JSONL evidence store and transport integration).
- GitHub Actions run #64, commit `4c44ce2`: **success** on Python 3.12, 3.13, and 3.14. 57 tests passed; Ruff passed in all matrix jobs (loopback HTTP transport).
- GitHub Actions run #57, commit `727320a`: **success** on Python 3.12, 3.13, and 3.14. 51 tests passed; Ruff passed in all matrix jobs (structured telemetry).
- GitHub Actions run #27, commit `9721aa5`: **success** on Python 3.12, 3.13, and 3.14. 25 tests passed; Ruff passed in all matrix jobs (M1).
- GitHub Actions run #45, commit `b69704b`: **success** on Python 3.12, 3.13, and 3.14. 41 tests passed; Ruff passed in all matrix jobs (M2 HTTP engine).
- No local test run has been performed from a local checkout in this session.

## Milestones

### M0 — Foundation — COMPLETE
Repository conventions, architecture, requirements, threat model, packaging baseline.

### M1 — Configuration and discovery — COMPLETE
Versioned config, decoy profile registry, protocol compatibility, read-only host discovery, CLI, docs, tests, and green CI matrix.

### M2 — Safe protocol simulation — IN PROGRESS
HTTP then HTTPS/TLS emulation; coherent per-session identities; fabricated safe responses; no shell or production backend forwarding.

### M3 — Telemetry and evidence — IN PROGRESS
Structured event schema, session correlation, monotonic ordering, append-only hash-chained JSONL storage, durable append/fsync, verification, export/retention.

### M4 — Isolation prototype
Threat-modelled runtime, default-deny egress, no host mounts/credentials, least privilege, resource limits, namespaces/cgroups/seccomp; disposable VM tier for higher risk. Escape testing is a release gate.

### M5 — Fail-closed traffic enforcement
Independent enforcement; MIRAGE crash, policy parse failure, or telemetry outage cannot expose production services. No deployment until failure-injection tests pass.

### M6 — Intelligence and operator experience
Evidence-backed correlation with confidence/provenance, operator API/UI, alerting, audit/export.

## Key files
- src/mirage/telemetry/store.py — append-only JSONL evidence store with SHA-256 chain verification and fsync.
- docs/evidence-storage.md — evidence envelope, durability, locking, permissions, and integrity limitations.
- ROADMAP.md — canonical roadmap and new-chat handoff.
- src/mirage/config/models.py — immutable typed models.
- src/mirage/config/validation.py — port/protocol compatibility rules.
- src/mirage/config/loader.py — TOML loading and structural validation.
- src/mirage/config/registry.py — profile resolution and registry validation.
- src/mirage/discovery/ports.py — read-only Linux socket discovery.
- src/mirage/emulation/http.py — pure HTTP decoy response engine; no socket listener.
- src/mirage/cli.py — CLI.
- config/example.toml — example configuration.
- docs/configuration.md — TOML schema and validation rules.
- docs/protocol-simulation.md — M2 design and security boundaries.
- tests/ — automated tests.
- .github/workflows/python.yml — CI matrix.

## M3 initial implementation — CI VERIFIED
- [x] Specify JSONL envelope, SHA-256 hash-chain, synchronous append/fsync semantics, locking, permissions, and known integrity limitations in `docs/evidence-storage.md`.
- [x] Implement private-mode JSONL append with a global hash chain, exclusive file locking, complete-chain verification before append, and fsync-before-acknowledgement.
- [x] Reject symlinks, hard links, non-regular files, unsafe permissions, malformed/incomplete records, duplicate JSON keys, and hash-chain tampering.
- [x] Verify concurrent appenders serialize into one valid chain using an OS-level file lock.
- [x] Connect the HTTP transport event sink to the durable store; a successful decoy response follows a persisted and verifiable event.
- [x] CI run #116 passed 73 tests and Ruff on Python 3.12, 3.13, and 3.14.
- [ ] Design external head-hash anchoring and safe export/retention before adding automatic deletion or claiming whole-file tamper detection.

## Resume here — exact next steps
1. Review ambiguous-commit/retry behaviour and duplicate event IDs; define safe idempotency semantics.
2. Add externally anchored checkpoints so whole-file rewrite or truncation can be detected; a local unanchored hash chain alone cannot provide this guarantee.
3. Define evidence export and retention semantics that preserve chain continuity and checkpoint provenance.
4. Measure append/verification throughput and design a bounded queue/backpressure strategy only if synchronous fsync is insufficient.
5. Keep public binding, production traffic interception, and decoy execution out of scope until isolation and independent fail-closed enforcement are implemented and tested.

## Handoff log
- 2026-11-03: Created durable roadmap/handoff with architecture decisions, milestones, and resume steps.
- 2026-11-03: Completed M1 configuration, registry, discovery, CLI, docs, and CI verification (run #27 green on Python 3.12–3.14).
- 2026-11-03: Started M2 with a transport-free deterministic HTTP decoy engine, bounded strict parser, fixed fabricated routes, and profile/header safety checks. CI run #45 passed 41 tests and Ruff on Python 3.12–3.14.

- 2026-11-03: Added the immutable session event model, per-session sequence/correlation, UTC timestamps, source metadata validation, query-string removal, and opt-in sanitized User-Agent capture. Added focused unit tests; CI verification pending.
- 2026-11-03: Corrected a Ruff import-style finding; GitHub Actions run #57 passed 51 tests and Ruff on Python 3.12–3.14. Structured telemetry model is now CI-verified.
- 2026-11-03: Added the opt-in loopback-only HTTP server with bounded header reads, request timeouts, active-connection limits, event-sink-before-response behaviour, and explicit shutdown. GitHub Actions run #64 passed 57 tests and Ruff on Python 3.12–3.14.
\n- 2026-11-03: Hardened the loopback HTTP transport: oversized headers are rejected, and telemetry sink exceptions close the connection without sending a decoy response. Added regression tests; CI verification pending.\n\n- 2026-11-03: Fixed escaped line endings in the two new transport tests; CI run #76 passed 59 tests and Ruff on Python 3.12–3.14. Oversized-header and telemetry-sink-failure behaviour is now verified.\n\n- 2026-11-03: Added `HttpsDecoyServer` using an explicit caller-supplied server-side TLS context, HTTPS profile enforcement, loopback-only binding, and bounded TLS handshake time. Added tests for trusted handshake, untrusted certificate rejection, and configuration restrictions; CI verification pending.\n\n- 2026-11-03: Fixed legacy HTTP-only expectation after extending the shared HTTP application engine to accept HTTPS profiles, and corrected TLS context validation test expectations. CI run #89 passed 62 tests and Ruff on Python 3.12–3.14; loopback HTTPS handshake and certificate verification are now verified.\n
- 2026-11-03: Tightened HTTPS server-context validation to require TLS 1.2 or newer. Added regression coverage for rejecting weaker TLS policy and closing TCP clients that never send a TLS ClientHello at the configured handshake timeout. CI verification pending.

- 2026-11-03: Hardened HTTPS policy to require TLS 1.2+, and tested stalled-handshake timeout cleanup; CI run #99 passed 63 tests and Ruff on Python 3.12–3.14.
- 2026-11-03: Started M3 with a documented append-only JSONL evidence format, SHA-256 hash chain, synchronous fsync, Linux file locking, restrictive file permissions, tamper/incomplete-record detection, and transport integration coverage. CI verification pending.

- 2026-11-03: Fixed duplicate-JSON-key verification handling and corrected CRLF framing in the durable-store transport integration test. CI run #116 passed 73 tests and Ruff on Python 3.12–3.14; initial M3 store is CI-verified.

- 2026-11-03: M3 initial JSONL evidence store passed CI run #116: 73 tests and Ruff on Python 3.12–3.14. Store is append-only, hash-chained, fsync-before-ack, permission-restricted, locked across appenders, and integrated with the fail-closed local HTTP event sink.
