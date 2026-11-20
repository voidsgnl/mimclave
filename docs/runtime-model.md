# MIMCLAVE Runtime and Adaptive Deception Model

## Purpose

MIMCLAVE is a continuously operating, Linux-first defensive monitoring and adaptive-deception service. It is not a desktop application that must remain open. The privileged system service performs monitoring, policy evaluation, traffic steering, sandbox lifecycle management, evidence collection, and response. A future tray and desktop interface will be an optional operator client.

The central operating rule is:

> Observe continuously. Preserve normal service for legitimate traffic. Present a controlled deceptive environment to traffic assessed as hostile. Contain only when policy and evidence justify it.

## Traffic handling model

A passive sensor alone cannot guarantee that a scanner never sees real service information: the first probe could reach a protected listener before a later alert is raised. Therefore, production deployment requires a host-level enforcement point in front of protected listeners. The enforcement point is always present, but ordinary traffic is forwarded unchanged under policy; suspicious traffic is steered to deception.

1. **Observe:** Collect bounded network and connection metadata at the host boundary. Do not inspect unrelated host activity or collect payloads unless a specific protocol adapter requires them and policy permits it.
2. **Classify:** Correlate events into source/flow activity. Distinguish low-confidence anomalies from high-confidence scanning, enumeration, exploitation attempts, and decoy interaction.
3. **Select a response:** Apply a versioned policy with explicit confidence thresholds, allowlists, rate limits, and operator-defined protected-service mappings. A single weak signal must not automatically disrupt a legitimate client.
4. **Steer:** For traffic selected for deception, direct the flow to a compatible decoy endpoint in an isolated deception plane. Do not proxy the attacker to the real backend.
5. **Maintain consistency:** Keep a stable decoy persona for the relevant flow or tracked source window. Banners, TLS/application behaviour, routes, users, files, and simulated topology must agree.
6. **Observe the interaction:** Record protocol events and actions performed inside MIMCLAVE-controlled decoys. Preserve event order, session correlation, provenance, and tamper-evident evidence.
7. **Escalate cautiously:** Apply containment (for example, temporary source throttling or blocking) only when a policy threshold is met. Record the reason, scope, expiry, and result. Support automatic expiry and operator rollback.

## Two separate traffic outcomes

- **Normal/allowed traffic:** Continues to the configured real service without MIMCLAVE changing application semantics. MIMCLAVE may retain only the metadata required by the active monitoring policy.
- **Suspicious/hostile traffic:** Is directed to the decoy plane and never reaches the protected service. The decoy's identity is fabricated independently of the real service.

The classification and steering decision must happen before protected service data is returned. The implementation must test the first-packet/first-response boundary; detecting a scan after exposing a real banner is not sufficient.

## Runtime and trust boundaries

### Host service

The future system daemon starts at boot and runs without the desktop session. It owns the monitoring pipeline and coordinates policy, enforcement, decoy routing, sandbox lifecycle, and evidence. Privileged operations should be split into the smallest possible components; protocol emulators and parsers should not run with host-level privileges.

### Enforcement plane

Traffic enforcement is a small, independently managed component (for example, narrowly scoped kernel firewall/nftables rules or an equivalent supported mechanism). It must not depend on the health of the user-space MIMCLAVE process to prevent accidental access to protected backends. Rules are staged, validated, atomically activated where supported, audited, and recoverable. Unknown or unhealthy states must never fall through to a protected service.

### Deception plane

Decoy listeners and protocol handlers run separately from the host service. Each decoy receives only its configured profile and the minimum event channel needed to report activity. It receives no production credentials, unrestricted host mounts, or route to protected networks.

### Sandbox plane

All attacker-controlled interaction is treated as hostile and remains inside an isolated sandbox. The initial tier should prefer deterministic protocol simulation and fabricated in-memory filesystems. Any real process execution is a later, separately reviewed tier requiring namespaces, cgroups, capability reduction, syscall filtering, resource quotas, default-deny egress, and no host credentials or writable host mounts. Higher-risk exploit observation belongs in disposable VMs with snapshots and a separately controlled virtual network. A container is not automatically a sufficient security boundary.

Sandbox escape, host access, protected-network reachability, resource exhaustion, and evidence-channel abuse are release-gate tests. If isolation cannot be verified, the feature remains disabled.

## Real-time requirements

- Use bounded event queues and explicit backpressure; overload must not silently drop security-critical events or permit unsafe traffic fallback.
- Bound classification time and make the policy decision before forwarding application data to a protected service.
- Keep per-flow/session state with expiry and limits to prevent memory exhaustion.
- Make decoy persona selection deterministic for the life of a session.
- Separate detection confidence from response severity. Detection does not automatically mean blocking.
- Emit an auditable event for each steering or containment decision, including policy version and reason codes.
- Measure detection latency, steering latency, event loss, and enforcement convergence under load.

## Failure behaviour

- If the monitoring process crashes, the independent enforcement plane must not send uncertain or suspicious traffic to a protected backend.
- If the policy is invalid, stale, or unavailable, do not activate a permissive fallback.
- If the sandbox is unhealthy, stop assigning new hostile sessions to it; never fall back to a real service.
- If evidence persistence is required by policy and fails, do not silently continue an unrecorded deception session.
- Recovery must reconcile actual kernel/network state with the last validated policy before accepting traffic.

## Operator experience — later phase

The operator experience is deliberately not part of the first runtime milestone.

- A lightweight system-tray client will show daemon health, monitoring state, active alerts, and whether a response is in effect.
- A full desktop dashboard will open only when the operator wants to configure MIMCLAVE or inspect live activity, sessions, evidence, policy decisions, and sandbox health.
- Closing or never launching either interface must not stop or weaken the daemon.
- The UI will communicate with a local authenticated management API; it will not own privileged enforcement or sandbox processes.

The tray and desktop dashboard are scheduled only after the monitoring, traffic steering, sandbox isolation, evidence, and recovery paths are implemented and tested.

## Implementation sequence

1. Specify and test sandbox boundaries using deterministic decoys first.
2. Build the always-on monitoring/event pipeline and real-time policy decision model.
3. Implement the independent enforcement adapter in a non-production test environment.
4. Implement selective traffic steering and prove legitimate traffic and suspicious traffic take separate paths.
5. Integrate isolated decoy sessions, evidence, and policy-based containment.
6. Add systemd service lifecycle, health checks, upgrade/recovery behaviour, and operational hardening.
7. Only then build the tray client and full desktop dashboard.

## Current implementation boundary

The current HTTP and SSH adapters are loopback-only prototypes. The SSH adapter uses a fabricated in-memory terminal; it is not a hardened sandbox. Production interception, selective steering, independent enforcement, system daemon lifecycle, and desktop management UI are not implemented. Do not expose the prototypes to a LAN or place them in front of production services.
