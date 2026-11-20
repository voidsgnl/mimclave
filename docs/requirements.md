# MIMCLAVE Requirements

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
- **FR-011:** Do not imply that MIMCLAVE can observe arbitrary commands executed locally on a remote attacker's own device.

### Isolation and containment
- **FR-012:** Keep protected services inaccessible from decoy network namespaces and workloads.
- **FR-013:** Deny outbound traffic from decoys by default; allow only explicit, narrowly scoped destinations for controlled experiments.
- **FR-014:** Apply resource limits and per-session isolation.
- **FR-015:** Ensure decoy failure cannot cause traffic to fall through to a protected backend.
- **FR-016:** Provide disposable execution environments only after independent isolation and escape testing.

### Telemetry, evidence, and intelligence
- **FR-017:** Record session timestamps, source network metadata, protocol events, commands entered into MIMCLAVE, responses returned, and containment events.
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
- **NFR-003:** Network enforcement must remain effective if the MIMCLAVE application crashes.
- **NFR-004:** Default-deny network and filesystem access for decoy workloads.
- **NFR-005:** Secrets must not be committed or written to ordinary logs.
- **NFR-006:** Tests must cover protocol compatibility, invalid mappings, fail-closed behaviour, and isolation boundaries.
- **NFR-007:** Exposure and containment changes must be auditable.

## Initial implementation scope

Milestone 1: project skeleton, typed configuration models, protocol-port compatibility validation, and unit tests. Service discovery should be read-only. No live interception, privileged networking, exploit execution, or general-purpose shell is in scope for the first milestone.


## Continuous monitoring and adaptive deception

- **FR-026:** Run the monitoring and policy engine as a persistent Linux system service independent of the user's desktop session.
- **FR-027:** Observe network activity continuously while preserving normal traffic handling for flows allowed by policy.
- **FR-028:** Place an independent enforcement point before protected listeners so traffic can be classified and steered before protected application data is disclosed.
- **FR-029:** Direct policy-selected suspicious traffic to a compatible decoy without forwarding that traffic to the protected backend.
- **FR-030:** Maintain a coherent fabricated identity for each decoy session, including protocol behaviour, banners, application routes, and simulated host data.
- **FR-031:** Keep all attacker-controlled interactions inside a sandboxed deception plane; a decoy compromise must not create host, production-service, credential, or internal-network access.
- **FR-032:** Separate detection confidence from response severity. Detection alone must not automatically block or disrupt a source.
- **FR-033:** Record each traffic-steering and containment decision with timestamp, source/flow correlation, policy version, reason code, action, expiry, and outcome.
- **FR-034:** Apply containment only when an explicit policy threshold is met; support bounded duration, automatic expiry, audit, and operator rollback.
- **FR-035:** Keep monitoring and enforcement operational when no tray or desktop dashboard is open.

## Operator interface — deferred

- **FR-036:** Provide a lightweight tray client for daemon health, monitoring state, and alerts after the core runtime is stable.
- **FR-037:** Provide a full desktop dashboard for configuration and investigation of live activity, evidence, policy decisions, and sandbox health.
- **FR-038:** Authenticate and audit management API operations; the UI must not own privileged enforcement or sandbox lifecycle.

## Additional non-functional and security requirements

- **NFR-008:** Monitoring and steering decisions must meet measured latency and throughput targets; targets must be established through load testing before production claims.
- **NFR-009:** The enforcement plane must fail closed and must not fall through to protected services when MIMCLAVE, policy, telemetry, or a decoy becomes unhealthy.
- **NFR-010:** Detection and response must be independently configurable; weak or ambiguous signals must not automatically disrupt legitimate traffic.
- **NFR-011:** Sandboxes must default-deny egress, have no production credentials or unrestricted host mounts, and enforce CPU, memory, process, disk, and session limits.
- **NFR-012:** The system daemon must start at boot and remain functional without a graphical session.
- **NFR-013:** Tray/dashboard availability must not affect monitoring, enforcement, evidence collection, or sandbox operation.
