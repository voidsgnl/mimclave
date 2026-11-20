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



## Product operating model — clarified 2026-11-20

MIRAGE is a continuously running system-level monitor and adaptive-deception service, not a desktop application that must stay open.

- **Observe continuously:** A background Linux daemon monitors traffic and correlates activity in real time.
- **Preserve legitimate traffic:** Normal flows continue to their configured real services under policy.
- **Disguise hostile-facing surfaces:** An enforcement point must sit before protected services can disclose application data. Suspicious flows are steered to coherent fabricated services; they are never forwarded to the real backend.
- **Sandbox everything attacker-controlled:** Decoy interactions remain isolated from the host, production services, credentials, and internal networks. The current virtual terminal is simulation, not a hardened sandbox.
- **Intervene selectively:** Detection and containment are separate. Blocking or throttling occurs only when an explicit policy threshold is met, with audit, expiry, and rollback.
- **Keep the UI optional:** A tray client and full desktop dashboard are a later phase, after the daemon, monitoring, steering, sandbox, evidence, and recovery paths work. Closing the UI must not affect operation.

The detailed design and release gates are in [docs/runtime-model.md](docs/runtime-model.md). The current loopback HTTP/SSH prototypes are not production interception, not hardened sandboxes, and must not be exposed beyond loopback.

## Status — 2026-11-04
**M0 — project foundation: complete.**  
**M1 — configuration and read-only discovery: COMPLETE.**  
**M2 — safe protocol simulation: pure HTTP engine, structured session-event model, loopback-only HTTP/HTTPS transports, and TLS 1.2 minimum policy implemented and CI-verified on Python 3.12–3.14.**
**M3 — telemetry and evidence: legacy append-only hash-chained JSONL store, idempotent append, verified export, and HTTPS external-checkpoint client are CI-verified. An initial separate `SegmentedEvidenceStore` implements manifest chaining, anchored rotation, recovery of interrupted segment transitions, and operator-approved retirement. GitHub Actions run #216 passed **116 tests and Ruff on Python 3.12, 3.13, and 3.14**. Six injected crash-boundary tests cover checkpoint publication, manifest sealing, successor creation, and retirement. Manifest tampering/truncation, missing/unmanifested segment files, and checkpoint verification across a retired prefix are also tested. An explicit non-destructive legacy-log migration API is implemented and CI-verified. It rejects oversized source logs and publishes with atomic no-replace rename, preventing destination overwrite races. GitHub Actions run #251 passed 132 tests and Ruff on Python 3.12–3.14. Additional crash injection covers initialization, manifest/segment fsync ordering, append acknowledgement and partial-write behaviour, rotation, retirement, and migration publication; checkpoint-prefix edge cases are also tested. Exhaustive filesystem-boundary coverage and target-hardware benchmarks remain outstanding. A SQLite-backed checkpoint service with append-only history and systemd/Caddy deployment examples is implemented and CI-verified; it is not yet deployed or independently audited.**

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

### M2 delivered
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
- GitHub Actions run #169, commit `23287bb`: **success** on Python 3.12, 3.13, and 3.14. 93 tests, Ruff, and the 10-event evidence benchmark smoke test passed in all matrix jobs (HTTPS checkpoint client).
- GitHub Actions run #151, commit `b58be40`: **success** on Python 3.12, 3.13, and 3.14. 82 tests, Ruff, and the 10-event evidence benchmark smoke test passed in all matrix jobs.
- GitHub Actions run #142, commit `c35b905`: **success** on Python 3.12, 3.13, and 3.14. 82 tests passed; Ruff passed in all matrix jobs (verified evidence export and checkpoint validation).
- GitHub Actions run #135, commit `eb0414a`: **success** on Python 3.12, 3.13, and 3.14. 79 tests passed; Ruff passed in all matrix jobs (external checkpoint interface, anchored-prefix verification, rollback/replacement detection).
- GitHub Actions run #123, commit `85b6fe0`: **success** on Python 3.12, 3.13, and 3.14. 75 tests passed; Ruff passed in all matrix jobs (idempotent evidence append and conflict handling).
- GitHub Actions run #116, commit `9125a26`: **success** on Python 3.12, 3.13, and 3.14. 73 tests passed; Ruff passed in all matrix jobs (initial M3 JSONL evidence store and transport integration).
- GitHub Actions run #64, commit `4c44ce2`: **success** on Python 3.12, 3.13, and 3.14. 57 tests passed; Ruff passed in all matrix jobs (loopback HTTP transport).
- GitHub Actions run #57, commit `727320a`: **success** on Python 3.12, 3.13, and 3.14. 51 tests passed; Ruff passed in all matrix jobs (structured telemetry).
- GitHub Actions run #27, commit `9721aa5`: **success** on Python 3.12, 3.13, and 3.14. 25 tests passed; Ruff passed in all matrix jobs (M1).
- GitHub Actions run #45, commit `b69704b`: **success** on Python 3.12, 3.13, and 3.14. 41 tests passed; Ruff passed in all matrix jobs (M2 HTTP engine).
- No local test run has been performed from a local checkout in this session.
- Documentation-only commits since run #169 (`bcd74ee`, `0e9dca6`, `5a43234`, and the decisions commit that follows them) changed no code; their CI results have not been checked.

## Milestones

### M0 — Foundation — COMPLETE
Repository conventions, architecture, requirements, threat model, packaging baseline.

### M1 — Configuration and discovery — COMPLETE
Versioned config, decoy profile registry, protocol compatibility, read-only host discovery, CLI, docs, tests, and green CI matrix.

### M2 — Safe protocol simulation — COMPLETE
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
- docs/evidence-segments.md — segmented rotation/retention design and recorded decisions (not implemented).
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
- [x] Idempotent append: identical event ID/payload retries return the original receipt; conflicting payload reuse raises `EvidenceEventConflictError`; duplicate IDs in existing logs are rejected.
- [x] CI run #123 passed 75 tests and Ruff on Python 3.12, 3.13, and 3.14.
- [x] Define `CheckpointAnchor` with monotonic generations and atomic compare-and-set; implement checkpoint publication and anchored-prefix verification.
- [x] Test that anchored checkpoints detect log truncation and replacement, and that compare-and-set conflicts are surfaced.
- [x] Add verified full-chain export with optional checkpoint verification, private destination permissions, no-overwrite semantics, and fsync.
- [x] CI run #135 passed 79 tests and Ruff on Python 3.12, 3.13, and 3.14.
- [x] Add verified full-chain export with optional checkpoint verification, private destination permissions, no-overwrite semantics, and fsync.
- [x] CI run #142 passed 82 tests and Ruff on Python 3.12, 3.13, and 3.14.
- [x] Define an external checkpoint contract with monotonic generations, atomic compare-and-set, and local-prefix verification; test rollback and replacement detection.
- [x] Implement an HTTPS external-anchor client using verified TLS, bearer authentication, bounded responses, redirect refusal, and ETag conditional writes.
- [x] CI run #169 passed 93 tests and Ruff on Python 3.12, 3.13, and 3.14; the benchmark smoke test also passed.
- [x] Draft the segmented rotation/retention design (one continuous chain, hash-chained segment manifest, checkpoint-anchored rotation, operator-approved retirement) and record its decisions in `docs/evidence-segments.md`; design only.
- [x] Confirm event IDs are generated with UUIDs and implement the initial segment manifest, continuous chain, anchored rotation, interrupted-transition recovery, and operator-approved retirement in `src/mirage/telemetry/segmented.py`.
- [x] Add targeted crash-injection tests for interruption before/after checkpointed sealing, before/after successor creation, and before/after retirement unlink; CI run #212 passed 111 tests and Ruff on Python 3.12–3.14.
- [x] Add manifest hash/tail tampering, missing/unmanifested segment, and retired-prefix checkpoint tests; CI run #216 passed 116 tests and Ruff on Python 3.12–3.14.
- [x] Add non-destructive legacy single-file migration API, reject oversized sources, and atomically publish without replacing existing/racing destinations; CI run #251 passed 132 tests and Ruff on Python 3.12–3.14.
- [x] Add `mirage migrate-evidence` CLI using the HTTPS checkpoint client and environment-only bearer-token handling; CI run #257 passed 134 tests and Ruff on Python 3.12–3.14.
- [x] Add crash-injection tests for initialization, fsync/acknowledgement, partial writes, rotation successor durability, and migration publication; add checkpoint-prefix edge-case tests. CI run #238 passed 130 tests and Ruff on Python 3.12–3.14.
- [ ] Extend crash injection to exhaustive syscall/filesystem-boundary coverage and add further cross-segment checkpoint edge cases.
- [x] Extend the benchmark harness to compare legacy JSONL and segmented append/verification and exercise rotation in CI (run #245).
- [ ] Collect repeatable target-Linux benchmark measurements before choosing operational segment limits; CI timing is not a performance baseline.
- [x] Implement a SQLite-backed checkpoint service with durable conditional compare-and-set, append-only hash-chained history, loopback-only listener, and deployment examples; CI run #277 passed 146 tests and Ruff on Python 3.12–3.14.
- [ ] Deploy the service on a separate, independently administered host; validate TLS termination, token storage, backup/restore, monitoring, and access controls before calling it an independent production anchor.

## Resume here — exact next steps
1. Validate the runnable local HTTP prototype on Python 3.12–3.14: run the full test suite and Ruff, then exercise the documented `serve-http` → `curl` → `verify-evidence` workflow on Ubuntu. The prototype must remain loopback-only.
2. [x] Add verified operator session inspection with activity timelines, path/status summaries, and conservative heuristic indicators. Activity clusters are source/profile/idle-time groupings, not authenticated identity sessions.
3. [x] Build the deterministic in-memory interactive decoy environment and add an experimental loopback-only SSH adapter. The adapter records redacted command metadata before returning simulated output; CI verification is pending.
4. **Next engineering phase — sandbox boundary:** specify and test the first isolation tier for deterministic decoys, then add a hardened workload tier only after threat review. Define the daemon/privilege split, default-deny egress, no host mounts or credentials, resource limits, session isolation, and disposable-VM escalation. See `docs/runtime-model.md`.
5. Build the always-on monitor and policy decision pipeline, then implement an independent enforcement adapter and selective steering in a controlled test environment. Prove the first-response boundary, legitimate-flow continuity, hostile-flow diversion, crash behaviour, telemetry outage, rollback, and bypass resistance before any production deployment.
6. Deploy and independently validate the checkpoint service on a separately administered host before treating it as an independent evidence anchor. Continue target-Linux evidence benchmarks and exhaustive crash-boundary tests.
7. Update this roadmap and CHANGELOG after each meaningful change.

## Local prototype milestone — 2026-11-20
- Added `mirage serve-http`, a runnable HTTP-only local decoy command. It validates the selected profile, refuses non-loopback bind addresses, uses the existing deterministic HTTP emulator, and appends each successful interaction to the hash-chained JSONL evidence store before returning the response.
- Added `mirage verify-evidence` for operator verification of the local JSONL evidence chain.
- Added `config/prototype-http.toml` and end-to-end tests covering an actual loopback request, evidence persistence, query-string exclusion, non-loopback rejection, HTTPS-profile rejection, and unmapped-profile rejection.
- This is a local demonstration only. It does not intercept production traffic, forward to protected services, modify firewall rules, or execute arbitrary commands. CI verification is pending.

## Session intelligence milestone — 2026-11-20
- Added `mirage inspect-sessions`, which verifies the complete JSONL evidence chain under a shared file lock before reading event payloads.
- Added activity clustering by source IP, decoy profile, and configurable inactivity window; reports include first/last seen, request timeline, methods, paths, status counts, and deterministic triage indicators.
- Current indicators cover sensitive-path probes, distinct 404 sweeps, repeated paths, and high request rates. They are heuristic observations, not proof of malicious intent or user identity.
- Collection remains conservative: request bodies, query strings, cookies, authorization headers, and User-Agent values are not added to this report.
- Added unit and CLI tests. CI verification is pending.

## Sandbox policy model milestone — 2026-11-20\n- Added immutable sandbox tier, network mode, and resource-limit models with fail-closed validation for policy identifiers, namespace sets, seccomp profile names, privilege flags, host mounts, host credentials, and tier-specific requirements.\n- Added tests for safe simulation defaults, isolated-worker requirements, disposable-VM lifecycle requirements, resource bounds, and malformed policy values.\n- This is declarative policy validation only. It does not create namespaces, cgroups, seccomp filters, VMs, or network rules. CI verification is pending.\n\n## Sandbox worker IPC contract milestone — 2026-11-20\n- Added a strict, bounded newline-delimited JSON event contract for worker-to-supervisor messages. It accepts only an explicit metadata allowlist and rejects unknown fields, duplicate JSON keys, oversized frames, invalid timestamps/IPs, query-bearing paths, raw command strings, and malformed identifiers.\n- Added per-session monotonic sequence enforcement and an active-session bound. The sequence guard is designed for serialized broker use; it is not itself an IPC server.\n- CI run #377 passed 265 tests, evidence benchmark smoke test, and Ruff on Python 3.12, 3.13, and 3.14.\n- No IPC socket, evidence broker process, namespace launcher, cgroup, seccomp filter, or sandbox runtime has been implemented yet.\n\n## Sandbox worker event broker milestone — 2026-11-20\n- Added a Linux Unix-domain-socket broker that authenticates peer UIDs with SO_PEERCRED, enforces private socket and parent-directory ownership/modes, refuses active or ambiguous stale socket replacement, bounds clients and frames, validates one session per connection, monotonic event sequences, recent session replay, idle timeouts, and orderly shutdown. The broker assigns the trusted profile ID and receipt timestamp; worker-claimed source addresses are not persisted until trusted supervisor registration.\n- Added a CLI service, `mirage serve-worker-broker`, with same-UID private-socket defaults and an explicit allowlisted worker-UID/group mode. Added tests for valid event persistence, wrong UID, invalid sequence, cross-session connection reuse, insecure directories, path preservation, active socket protection, group socket permissions, and SSH command metadata.\n- This broker is not yet connected to HTTP/SSH transports or a launched worker process. Same-UID development mode is not isolation. GitHub Actions run #417 passed 282 tests, the evidence benchmark smoke test, and Ruff on Python 3.12–3.14. The next step is a trusted session-registration handshake so the supervisor can bind the accepted client peer address and session metadata before worker events are accepted.\n\n## Handoff log
- 2026-11-03: Created durable roadmap/handoff with architecture decisions, milestones, and resume steps.
- 2026-11-03: Completed M1 configuration, registry, discovery, CLI, docs, and CI verification (run #27 green on Python 3.12–3.14).
- 2026-11-03: Started M2 with a transport-free deterministic HTTP decoy engine, bounded strict parser, fixed fabricated routes, and profile/header safety checks. CI run #45 passed 41 tests and Ruff on Python 3.12–3.14.

- 2026-11-03: Added the immutable session event model, per-session sequence/correlation, UTC timestamps, source metadata validation, query-string removal, and opt-in sanitized User-Agent capture. Added focused unit tests; CI verification pending.
- 2026-11-03: Corrected a Ruff import-style finding; GitHub Actions run #57 passed 51 tests and Ruff on Python 3.12–3.14. Structured telemetry model is now CI-verified.
- 2026-11-03: Added the opt-in loopback-only HTTP server with bounded header reads, request timeouts, active-connection limits, event-sink-before-response behaviour, and explicit shutdown. GitHub Actions run #64 passed 57 tests and Ruff on Python 3.12–3.14.
- 2026-11-03: Hardened the loopback HTTP transport: oversized headers are rejected, and telemetry sink exceptions close the connection without sending a decoy response. Added regression tests; CI verification pending.
- 2026-11-03: Fixed escaped line endings in the two new transport tests; CI run #76 passed 59 tests and Ruff on Python 3.12–3.14. Oversized-header and telemetry-sink-failure behaviour is now verified.
- 2026-11-03: Added `HttpsDecoyServer` using an explicit caller-supplied server-side TLS context, HTTPS profile enforcement, loopback-only binding, and bounded TLS handshake time. Added tests for trusted handshake, untrusted certificate rejection, and configuration restrictions; CI verification pending.
- 2026-11-03: Fixed legacy HTTP-only expectation after extending the shared HTTP application engine to accept HTTPS profiles, and corrected TLS context validation test expectations. CI run #89 passed 62 tests and Ruff on Python 3.12–3.14; loopback HTTPS handshake and certificate verification are now verified.
- 2026-11-03: Tightened HTTPS server-context validation to require TLS 1.2 or newer. Added regression coverage for rejecting weaker TLS policy and closing TCP clients that never send a TLS ClientHello at the configured handshake timeout. CI verification pending.

- 2026-11-03: Hardened HTTPS policy to require TLS 1.2+, and tested stalled-handshake timeout cleanup; CI run #99 passed 63 tests and Ruff on Python 3.12–3.14.
- 2026-11-03: Started M3 with a documented append-only JSONL evidence format, SHA-256 hash chain, synchronous fsync, Linux file locking, restrictive file permissions, tamper/incomplete-record detection, and transport integration coverage. CI verification pending.

- 2026-11-03: Fixed duplicate-JSON-key verification handling and corrected CRLF framing in the durable-store transport integration test. CI run #116 passed 73 tests and Ruff on Python 3.12–3.14; initial M3 store is CI-verified.

- 2026-11-03: M3 initial JSONL evidence store passed CI run #116: 73 tests and Ruff on Python 3.12–3.14. Store is append-only, hash-chained, fsync-before-ack, permission-restricted, locked across appenders, and integrated with the fail-closed local HTTP event sink.

- 2026-11-03: Implemented idempotent append by stable event ID. Identical retries return the original receipt without a duplicate record; conflicting payload reuse is rejected; duplicate IDs in an existing log fail verification. Added regression tests; CI verification pending.

- 2026-11-03: Idempotent event append is CI-verified in run #123: 75 tests and Ruff on Python 3.12–3.14. A retry with the same event ID and identical payload returns the original receipt; a conflicting payload is rejected; duplicate IDs invalidate the log.

- 2026-11-03: Added the external checkpoint contract and store operations. Checkpoints commit generation, record count, and head hash; verification detects truncation and replacement of an anchored prefix. CI verification pending. Only the interface and an in-memory test double exist; no production remote anchor is included.

- 2026-11-03: External checkpoint interface and anchored-prefix verification passed CI run #135: 79 tests and Ruff on Python 3.12–3.14. Truncation and replacement of a previously anchored prefix are detected. No production remote anchor adapter is included; the tests use an in-memory contract implementation.

- 2026-11-03: Added verified evidence export. It verifies the full chain (and optional external checkpoint), copies without modifying the source, refuses overwrite, applies mode 0600, and fsyncs the file and directory. Automatic deletion/rotation remains out of scope. CI verification pending.

- 2026-11-03: Verified evidence export passed CI run #142: 82 tests and Ruff on Python 3.12–3.14. Export verifies the full chain and optional checkpoint, refuses overwrite, writes mode 0600, fsyncs file and directory, and leaves source unchanged. Automatic retention deletion remains intentionally unimplemented.

- 2026-11-03: Added `scripts/benchmark_evidence_store.py` and a 10-event CI smoke test. The script reports append and full-verification throughput using a temporary file; target-hardware measurements remain pending. CI verification pending.

- 2026-11-03: Benchmark smoke test passed in CI run #151 on Python 3.12–3.14. The short CI sample is only an execution check, not a performance baseline; target Linux measurements remain pending.

- 2026-11-03: Corrected the handoff to mark M2 complete and clarify remaining M3 work: production external anchor adapter, segmented retention/rotation, and target-hardware performance measurements. The benchmark CI smoke test is verified but is not a performance baseline.

- 2026-11-03: Added `HttpsCheckpointAnchor`: verified TLS, bearer authentication, no redirects, bounded response size, strong ETag validation, conditional create/update, and conflict handling. A separate hosted service is still required. CI verification pending.

- 2026-11-03: HTTPS checkpoint client passed CI run #169: 93 tests, Ruff, and benchmark smoke test on Python 3.12–3.14. The client enforces HTTPS, default certificate validation, no redirects, bounded JSON responses, bearer-token hygiene, strong ETags, conditional create/update, and conflict handling. A separately hosted service remains a deployment dependency.

- 2026-11-04: Fixed escaped newline artifacts in this handoff log and renamed the stale "M2 started" heading to "M2 delivered" (commit `bcd74ee`, documentation only).
- 2026-11-04: Added `docs/evidence-segments.md`, a design proposal for segmented evidence rotation and operator-approved retention (commit `0e9dca6`, documentation only).
- 2026-11-04: Recorded decisions for the segmented evidence design: sealed segments verified on every append by default (`verify_sealed_on_append=True`), anchor history deferred, no hard-coded segment size defaults, event-ID reuse across retired segments accepted as a limitation. Documentation only. Next task: implement the manifest, rotation, crash recovery, and retirement with tests, after confirming event IDs are generated uniquely.


- 2026-11-08: Added the initial `SegmentedEvidenceStore` alongside the legacy JSONL store. Implemented a hash-chained manifest, continuous evidence chain/global numbering, external-checkpoint-gated sealing, hard segment limits, interrupted-transition recovery, retained-segment idempotency, and operator-approved oldest-first retirement. Added focused tests and documented the API. CI and broader crash-injection/security validation remain pending; no production anchor service or target-hardware benchmark is included.


- 2026-11-08: Segmented evidence implementation passed GitHub Actions run #208 on Python 3.12, 3.13, and 3.14: **105 tests and Ruff passed**. Coverage includes automatic rotation, anchor mismatch/outage handling, sealed-segment tampering, retirement, and recovery of interrupted sealing/opening transitions. Exhaustive crash-boundary testing, migration tooling, hosted anchor deployment, and target-hardware benchmarks remain open.


- 2026-11-08: Added six crash-injection tests covering checkpoint publication before sealing, manifest seal before chmod, sealed-segment fsync before successor manifest, successor manifest before file creation, retirement manifest before unlink, and unlink before directory fsync. GitHub Actions run #212 passed **111 tests and Ruff on Python 3.12, 3.13, and 3.14**. Remaining release-readiness work: exhaustive filesystem-boundary coverage, manifest-tampering tests, retired-boundary checkpoint edge cases, migration tooling, and target-hardware benchmarks.


- 2026-11-08: Added manifest integrity tests for edited entries and incomplete tails, directory reconciliation tests for missing sealed and unmanifested segment files, and a checkpoint-verification test after retiring the oldest segment while the latest checkpoint refers to a later retained boundary. GitHub Actions run #216 passed **116 tests and Ruff on Python 3.12, 3.13, and 3.14**.


- 2026-11-09: Implemented non-destructive legacy JSONL migration. The migration verifies the full source chain, checks and advances the external checkpoint to the source head, copies the original record bytes unchanged into sealed segment 1, creates the active successor, verifies the staged store, and atomically publishes the destination. The source remains untouched. Added tests for byte-for-byte preservation, source retention, tampering, and checkpoint conflicts. GitHub Actions run #227 passed **119 tests, the evidence benchmark smoke test, and Ruff on Python 3.12, 3.13, and 3.14**.

**Next engineering priorities**
1. Expand crash-injection coverage to every filesystem durability boundary in initialization, append, rotation, migration, and retirement.
2. Add a dedicated migration CLI only after the external checkpoint service configuration and secret-handling contract are finalized.
3. Run repeatable append, verification, rotation, and retention benchmarks on representative Linux storage.
4. Deploy and independently validate the hosted checkpoint service before any production evidence deployment.


- 2026-11-09: Expanded segmented-evidence fault-injection and checkpoint tests. Covered manifest fsync before initial segment creation, initialization after segment fsync, successor-file fsync before directory fsync, append fsync before receipt delivery (idempotent retry), partial record writes (fail closed without truncation), and migration failure before publication/after rename. Added checkpoint tests for a valid active-segment prefix, a checkpoint ahead of local evidence, and a checkpoint inside a retired segment. GitHub Actions run #238 passed **130 tests, the evidence benchmark smoke test, and Ruff on Python 3.12, 3.13, and 3.14**. Exhaustive syscall-boundary testing, target-Linux benchmarks, and hosted checkpoint deployment remain outstanding.


- 2026-11-09: Extended the evidence benchmark to compare legacy JSONL and segmented append/verification, reporting storage bytes and segment count. Added configurable segment sizing and changed the CI smoke test to force automatic rotation. The benchmark's in-memory checkpoint double excludes remote anchor latency. GitHub Actions run #245 passed tests, benchmark smoke, and Ruff on Python 3.12–3.14. Representative target-Linux measurements remain outstanding.


- 2026-11-09: Hardened migration publication with Linux `renameat2(RENAME_NOREPLACE)`, preventing an existing or racing destination from being replaced; migration now rejects a legacy source larger than the configured hard segment limit. Added regression tests for destination races and oversized sources. GitHub Actions run #251 passed **132 tests and Ruff on Python 3.12, 3.13, and 3.14**.


- 2026-11-09: Added the explicit `mirage migrate-evidence` CLI. It accepts source/destination paths, checkpoint URL, and segment limits; reads the bearer token only from an environment variable; never places the token in command arguments or output; and reports the verified migrated head. CLI tests cover missing-token handling and successful secret-safe execution. GitHub Actions run #257 passed **134 tests and Ruff on Python 3.12, 3.13, and 3.14**.


- 2026-11-09: Implemented the SQLite-backed checkpoint service with conditional ETag GET/PUT, serialized durable CAS updates, an append-only hash-chained checkpoint history, strict request validation, loopback-only binding, and high-entropy bearer-token requirements. Added systemd and Caddy deployment examples. CI run #277 passed **146 tests and Ruff on Python 3.12, 3.13, and 3.14**. The service is not deployed or independently audited; it must be installed on a separate host and backed up independently before it provides operational independence.


## Latest handoff — 2026-11-20

### Trusted supervisor registration foundation — implementation in progress
- Added a second private Unix-domain socket for supervisor-only session registration, separate from the worker event socket.
- Registration binds the session UUID to protocol, original client source IP/port, worker UID and worker PID. The broker authenticates the control peer with `SO_PEERCRED`, then verifies the worker's own PID/UID and protocol before accepting its first event.
- Registrations expire, are single-claim, and are removed when the worker connection closes. The broker records only supervisor-supplied source metadata and still owns evidence writes.
- The supervisor registration codec and broker API are foundations only: HTTP/SSH listeners do not yet register their accepted sockets or launch supervised workers. A same-UID development setup is not a security boundary against compromise of that UID. GitHub Actions run #449 passed 286 tests, the evidence benchmark smoke test, and Ruff on Python 3.12, 3.13, and 3.14. Local Ubuntu verification remains pending.
- Added `src/mirage/sandbox/supervisor.py` with a bounded async client for the private control socket. It sends the accepted peer metadata and exact worker UID/PID, requires an explicit broker acknowledgement, applies a timeout, and fails closed on rejection or malformed responses. Added integration tests proving the broker persists supervisor-registered source metadata and its own profile ID rather than worker claims. CI verification for this addition is pending.
- This is only the registration client, not a process supervisor or worker launcher. The next implementation step is a fixed-purpose worker lifecycle/launch mechanism with a start gate, identity drop, descriptor handoff, timeout, and cleanup; only after that should the HTTP/SSH listeners be connected.

### Session intelligence delivered
- Added `mirage inspect-sessions <evidence.jsonl>`, which verifies the complete JSONL hash chain before grouping events into heuristic activity clusters.
- Reports source/profile, first and last seen, route/status counts, timelines, and conservative triage indicators. Clusters are not authenticated sessions or identity attribution.
- The user successfully exercised this against four local HTTP requests. One cluster was reported with no indicators; the browser's `/favicon.ico` 404 was an ordinary missing-icon request.

### Initial virtual terminal simulator delivered
- Added `src/mirage/emulation/terminal.py` and `mirage simulate-terminal`.
- The interpreter uses only fabricated in-memory files, users, and process output. Supported commands: `help`, `whoami`, `hostname`, `pwd`, `id`, `uname`, `ls`, `cat`, `ps`, `cd`, and `clear`.
- Strictly rejects shell operators, redirects, pipes, expansions, traversal, excessive input, unsupported options, and unknown commands. No shell, subprocess, host filesystem, or network calls.
- The local simulator remains the command execution boundary. The experimental SSH adapter described below exposes it only on loopback; it is not a production or public honeypot.

### Experimental SSH transport milestone — 2026-11-20 (CI passed)
- Added optional AsyncSSH-based `SSHDecoyServer` and `mirage serve-ssh`. The listener requires a dedicated operator-provisioned host key with restrictive file permissions and accepts literal loopback addresses only.
- Each SSH process/channel receives a fresh in-memory `VirtualTerminal`; no host shell, subprocess, filesystem, network forwarding, SFTP, agent forwarding, or X11 is exposed.
- Added connection/session caps, login timeout, bounded SSH channel window, per-command absolute input deadline, 512-character command limit, and 100-command interactive session limit.
- SSH authentication is intentionally disabled for this local deception prototype. The server does not request or store passwords or client keys. It also omits usernames, full command lines, and arguments from evidence; only normalized command names and source/session metadata are recorded.
- Command output is sent only after the event sink has appended and fsynced the event. Evidence failure exits the SSH process without returning simulated output.
- Added tests for loopback/key policy, SSH exec command execution, callback-level per-session filesystem isolation, metadata redaction, and fail-closed evidence handling. GitHub Actions run #353 (run ID `44787629575`) passed the Python 3.12, 3.13, and 3.14 matrices, including tests, benchmark smoke test, and Ruff. Local Ubuntu verification is still pending.
- This remains a loopback-only prototype. Do not expose it to a LAN or the internet. It is not an isolated sandbox and does not provide independent network enforcement.

### CI blocker — investigate before release
- The latest `main` head before the virtual-terminal work was `0c44fcfdd74bba21b6518781c65e36d37a3231b7`.
- GitHub Actions run #302 (run ID `44775072812`) reported failure for all three Python matrix jobs. The job summaries returned no step data, and downloading job logs returned `BlobNotFound`; therefore the actual failure cause is unknown. Do not infer a source-code failure or claim CI is green.
- Previous successful CI run recorded in the historical log was #277. The failures across all matrix versions and near-immediate completion may indicate a runner/setup issue, but this remains unverified.
- No local checkout was available to execute pytest or Ruff during this session. After pulling the latest `main`, run:
  ```bash
  python -m pip install -e '.[dev]'
  python -m pytest -q
  python -m ruff check .
  ```
- If local tests pass, rerun or inspect the GitHub Actions workflow and obtain job-level logs before relying on CI.

### Current boundary and next work
- Current prototype: loopback HTTP decoy, experimental loopback SSH terminal adapter, hash-chained evidence, evidence verification, heuristic session inspection, and local in-memory terminal simulation. SSH CI passed on Python 3.12, 3.13, and 3.14; local Ubuntu verification is still pending.
- Still not implemented: production traffic interception, independent enforcement, isolated sandbox execution, management API/dashboard, and production deployment. The SSH transport is experimental and loopback-only; it does not constitute sandbox isolation.
- Preserve the local evidence log; never overwrite or silently reset it.
- Continue on `main`; do not create branches unless explicitly requested.
