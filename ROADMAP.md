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
**M2 — safe protocol simulation: pure HTTP engine, structured session-event model, loopback-only HTTP transport, and explicit HTTPS/TLS transport implemented; HTTPS verification pending CI.**

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
- [ ] Verify TLS handshake, certificate validation, and transport tests in CI across Python 3.12–3.14.

## CI verification record
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

### M3 — Telemetry and evidence
Structured event schema, session correlation, monotonic ordering, tamper-evident storage, export/retention.

### M4 — Isolation prototype
Threat-modelled runtime, default-deny egress, no host mounts/credentials, least privilege, resource limits, namespaces/cgroups/seccomp; disposable VM tier for higher risk. Escape testing is a release gate.

### M5 — Fail-closed traffic enforcement
Independent enforcement; MIRAGE crash, policy parse failure, or telemetry outage cannot expose production services. No deployment until failure-injection tests pass.

### M6 — Intelligence and operator experience
Evidence-backed correlation with confidence/provenance, operator API/UI, alerting, audit/export.

## Key files
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

## Resume here — exact next steps
1. Add structured session/request events with correlation IDs, source metadata supplied by a transport adapter, and an explicit redaction policy.
2. Implement an optional loopback-only HTTP transport adapter with connection/time limits and explicit shutdown. No public bind, backend forwarding, filesystem access, or shell execution.
3. Add integration tests for fragmented reads, slow clients, connection limits, and graceful shutdown.
4. Add TLS only after HTTP adapter security tests pass.
5. Update this roadmap and CHANGELOG after every meaningful change.

## Handoff log
- 2026-11-03: Created durable roadmap/handoff with architecture decisions, milestones, and resume steps.
- 2026-11-03: Completed M1 configuration, registry, discovery, CLI, docs, and CI verification (run #27 green on Python 3.12–3.14).
- 2026-11-03: Started M2 with a transport-free deterministic HTTP decoy engine, bounded strict parser, fixed fabricated routes, and profile/header safety checks. CI run #45 passed 41 tests and Ruff on Python 3.12–3.14.

- 2026-11-03: Added the immutable session event model, per-session sequence/correlation, UTC timestamps, source metadata validation, query-string removal, and opt-in sanitized User-Agent capture. Added focused unit tests; CI verification pending.
- 2026-11-03: Corrected a Ruff import-style finding; GitHub Actions run #57 passed 51 tests and Ruff on Python 3.12–3.14. Structured telemetry model is now CI-verified.
- 2026-11-03: Added the opt-in loopback-only HTTP server with bounded header reads, request timeouts, active-connection limits, event-sink-before-response behaviour, and explicit shutdown. GitHub Actions run #64 passed 57 tests and Ruff on Python 3.12–3.14.
\n- 2026-11-03: Hardened the loopback HTTP transport: oversized headers are rejected, and telemetry sink exceptions close the connection without sending a decoy response. Added regression tests; CI verification pending.\n\n- 2026-11-03: Fixed escaped line endings in the two new transport tests; CI run #76 passed 59 tests and Ruff on Python 3.12–3.14. Oversized-header and telemetry-sink-failure behaviour is now verified.\n\n- 2026-11-03: Added `HttpsDecoyServer` using an explicit caller-supplied server-side TLS context, HTTPS profile enforcement, loopback-only binding, and bounded TLS handshake time. Added tests for trusted handshake, untrusted certificate rejection, and configuration restrictions; CI verification pending.\n