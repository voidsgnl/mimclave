# MIRAGE Requirements

## Product objective

Provide a Linux-first platform that protects authorized infrastructure by exposing configurable protocol-compatible decoys, safely observing attacker interactions within those decoys, and preserving useful evidence for investigation.

## Functional requirements

### Discovery and configuration
- **FR-001:** Discover listening ports and local service metadata without changing host networking.
- **FR-002:** Maintain a protected-service inventory separately from decoy configuration.
- **FR-003:** Map an exposed endpoint to any compatible decoy profile; the decoy need not match the real backend.
- **FR-004:** Support reusable, versioned deception profiles.
- **FR-005:** Validate transport and protocol compatibility. Defaults should flag conventions such as HTTPS/TLS on TCP/443 and SSH on TCP/22, while allowing documented nonstandard deployments.
- **FR-006:** Validate port conflicts, listener ownership, TLS requirements, and profile completeness before activation.

### Deception and interaction
- **FR-007:** Emulate supported protocols with coherent banners, authentication flows, and application responses.
- **FR-008:** Provide configurable fake hostnames, users, credentials, files, processes, application data, and network topology.
- **FR-009:** Keep each session internally consistent.
- **FR-010:** Provide deterministic simulated command environments that record commands and arguments submitted inside the decoy.
- **FR-011:** Do not imply that MIRAGE can observe arbitrary commands executed locally on a remote attacker's own device.

### Isolation and containment
- **FR-012:** Keep protected services inaccessible from decoy network namespaces and workloads.
- **FR-013:** Deny outbound traffic from decoys by default; allow only explicit, narrowly scoped destinations for controlled experiments.
- **FR-014:** Apply resource limits and per-session isolation.
- **FR-015:** Ensure decoy failure cannot cause traffic to fall through to a protected backend.
- **FR-016:** Provide disposable execution environments only after independent isolation and escape testing.

### Telemetry, evidence, and intelligence
- **FR-017:** Record session timestamps, source network metadata, protocol events, commands entered into MIRAGE, responses returned, and containment events.
- **FR-018:** Preserve event ordering and session correlation identifiers.
- **FR-019:** Protect evidence integrity and record provenance.
- **FR-020:** Correlate repeated infrastructure and behavioural indicators with explainable confidence levels.
- **FR-021:** Distinguish observed facts, inferred relationships, and unknowns in reports.
- **FR-022:** Never assert a real-world identity solely from an IP address, user-agent, TLS fingerprint, or behavioural similarity.

### Management
- **FR-023:** Provide authenticated operator access and auditable configuration changes.
- **FR-024:** Support exportable session timelines and investigation reports.
- **FR-025:** Provide safe preview/test mode before network rules are activated.

## Non-functional and security requirements

- **NFR-001:** Linux is the initial supported host platform.
- **NFR-002:** The first milestone is read-only; no firewall changes or traffic redirection.
- **NFR-003:** Network enforcement must remain effective if the MIRAGE application crashes.
- **NFR-004:** Default-deny network and filesystem access for decoy workloads.
- **NFR-005:** Secrets must not be committed or written to ordinary logs.
- **NFR-006:** Tests must cover protocol compatibility, invalid mappings, fail-closed behaviour, and isolation boundaries.
- **NFR-007:** Exposure and containment changes must be auditable.

## Initial implementation scope

Milestone 1: project skeleton, typed configuration models, protocol-port compatibility validation, and unit tests. Service discovery should be read-only. No live interception, privileged networking, exploit execution, or general-purpose shell is in scope for the first milestone.
