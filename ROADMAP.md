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

## Status at 2026-11-03
**M0 — project foundation: complete.**  
**M1 — configuration and read-only discovery: in progress.**

### Implemented
- [x] Architecture, requirements, and threat-model documents.
- [x] Immutable endpoint, decoy profile, protected-service, and listener-mapping models.
- [x] Protocol/port compatibility checks and reason-required nonstandard overrides.
- [x] Read-only Linux `/proc/net` discovery for TCP listeners and bound UDP sockets.
- [x] `mirage discover` / `python -m mirage discover` CLI.
- [x] GitHub Actions test matrix for Python 3.12, 3.13, and 3.14.
- [x] Versioned TOML configuration loader.
- [x] Profile registry with mapping resolution, duplicate listener checks, and compatibility validation.
- [x] Example TOML config with backend inventory separated from decoy profile.

### Not complete / not verified
- [ ] Packaging metadata and install verified end-to-end.
- [ ] Full pytest and Ruff run; CI green status not yet confirmed.
- [ ] Config validation CLI and documented schema.
- [ ] Discovery-to-config comparison report (read-only).
- [ ] Protocol emulation, event model, evidence storage, isolation, fail-closed enforcement, intelligence, API/UI.

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
7. Package install, tests, lint, and CI pass.

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
- `src/mirage/config/models.py` — immutable typed models.
- `src/mirage/config/validation.py` — port/protocol compatibility rules.
- `src/mirage/config/loader.py` — TOML loading and structural validation.
- `src/mirage/config/registry.py` — profile resolution and registry validation.
- `src/mirage/discovery/ports.py` — read-only Linux socket discovery.
- `src/mirage/cli.py` — CLI.
- `config/example.toml` — example configuration.
- `tests/` — automated tests.
- `.github/workflows/python.yml` — CI matrix.

## Resume here — exact next steps
1. Fix and verify `pyproject.toml` (previous console-script edit may have malformed literal newline escapes).
2. Add `mirage validate-config config/example.toml`; return nonzero on invalid config and print each validation issue clearly.
3. Add loader/registry tests for malformed TOML, duplicate profile IDs, duplicate protected-service IDs, override reason, and UDP mappings.
4. Run `python -m pip install -e '.[dev]'`, `pytest -q`, and `ruff check .`; fix failures.
5. Check GitHub Actions and record the actual run result here.
6. Complete M1 before beginning M2 protocol emulation.

## Handoff log
- 2026-11-03: Created roadmap/handoff with project decisions, milestones, current status, and resume steps.
- 2026-11-03: Added TOML loader, profile registry, sample config, and loader tests. Fixed packaging metadata and verify it before considering M1 complete.
