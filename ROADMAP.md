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
**M1 — configuration and read-only discovery: implementation substantially complete; CI verification pending.**

### Implemented
- [x] Architecture, requirements, threat-model, and configuration-schema documents.
- [x] Immutable endpoint, decoy profile, protected-service, and listener-mapping models.
- [x] Versioned TOML loader with structural validation and actionable parse errors.
- [x] Profile registry with unique profile IDs, mapping resolution, duplicate listener and protected-service checks.
- [x] Protocol/port compatibility checks; deliberate mismatches require an explicit reason.
- [x] TCP conventions are not incorrectly applied to UDP mappings.
- [x] Example TOML config keeps real protected-service inventory separate from decoy identity.
- [x] Read-only Linux `/proc/net` discovery for TCP listeners and bound UDP sockets.
- [x] `mirage discover` / `python -m mirage discover` CLI.
- [x] `mirage validate-config <path>` CLI with distinct exit codes for valid, policy-invalid, and load-invalid configurations.
- [x] GitHub Actions matrix for Python 3.12, 3.13, and 3.14.
- [x] Fixed malformed console-script metadata in `pyproject.toml`.
- [x] Added durable project handoff and changelog updates.

### CI / verification
- Earlier runs exposed two real setup issues: malformed TOML in `pyproject.toml`, then Ruff import-order lint failures. The packaging metadata has been corrected and import-order lint was removed from the initial Ruff rule set; syntax, correctness, upgrade, and bugbear checks remain enabled.
- Latest observed workflow run: **Python checks run #20** (commit `08e4316`) was still in progress at the last check. Do not mark M1 complete until the latest run is green.
- Tests have passed on earlier CI commit `7aa9d72` after packaging was corrected, but that run predates the latest loader edge-case tests. Current full test matrix is pending.
- No local test run has been performed from a local checkout in this session.

## Milestones

### M0 — Foundation — COMPLETE
Repository conventions, architecture, requirements, threat model, packaging baseline.

### M1 — Configuration and discovery — IN PROGRESS
Exit criteria:
1. Config parsing rejects malformed/unsupported input with useful diagnostics.
2. Duplicate profile IDs and duplicate listener targets are rejected.
3. Missing profile references and protocol/port mismatches are rejected.
4. Overrides require a documented reason.
5. Real service inventory remains separate from decoy identity.
6. Read-only discovery is tested and labels TCP listeners vs UDP bound sockets accurately.
7. Package install, tests, lint, and CI pass on Python 3.12–3.14.

### M2 — Safe protocol simulation
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
- `ROADMAP.md` — canonical roadmap and new-chat handoff.
- `src/mirage/config/models.py` — immutable typed models.
- `src/mirage/config/validation.py` — port/protocol compatibility rules.
- `src/mirage/config/loader.py` — TOML loading and structural validation.
- `src/mirage/config/registry.py` — profile resolution and registry validation.
- `src/mirage/discovery/ports.py` — read-only Linux socket discovery.
- `src/mirage/cli.py` — CLI.
- `config/example.toml` — example configuration.
- `docs/configuration.md` — TOML schema and validation rules.
- `tests/` — automated tests.
- `.github/workflows/python.yml` — CI matrix.

## Resume here — exact next steps
1. Check the latest GitHub Actions run on `main`. If it fails, inspect job logs and fix the actual cause; do not assume tests passed.
2. Confirm all tests and Ruff checks pass on Python 3.12, 3.13, and 3.14.
3. If green, close M1 and move to the read-only discovery-to-config comparison/report. Do not enable traffic interception.
4. Then design M2 HTTP/TLS emulation, including session consistency and safe fabricated responses, before implementing listeners.
5. Keep this roadmap, changelog, and README synchronized after every meaningful change.

## Handoff log
- 2026-11-03: Created roadmap/handoff with project decisions, milestones, and resume steps.
- 2026-11-03: Added TOML loader, profile registry, sample config, validation CLI, schema documentation, and edge-case tests.
- 2026-11-03: Corrected `pyproject.toml` console script and adjusted Ruff lint selection after CI identified configuration/style failures. Latest CI verification is pending.
