# MIRAGE Sandbox Boundary Design

## Status

Design baseline for the next isolation milestone. This document is a security specification, not evidence that sandboxing is implemented. The existing loopback HTTP and SSH prototypes remain host-process prototypes; the SSH virtual terminal is an in-memory simulation, not an operating-system sandbox.

## Security objective

Treat every byte received from an untrusted client as hostile. Protocol parsing, authentication simulation, command simulation, and any future workload execution must not give the remote client a path to the host, production services, credentials, or internal networks.

A decoy must remain useful for observation while having no authority beyond its own fabricated environment.

## Trust domains

1. **Host enforcement:** Minimal privileged component that owns narrowly scoped traffic rules and protects backend reachability.
2. **MIRAGE supervisor:** Unprivileged where possible; validates policy, starts/stops workers, tracks health, and coordinates evidence.
3. **Decoy worker:** Handles one protocol session or a small explicitly bounded group of sessions. Treat the worker as potentially compromised.
4. **Evidence broker:** Owns evidence files and accepts bounded, validated event messages from workers. Workers never receive writable access to evidence storage.
5. **Protected services:** Separate trust domain. No worker route, mount, credential, or IPC permission grants access to it.

The privileged enforcement component must not load protocol payloads, parse attacker-controlled application data, or execute decoy logic.

## Isolation tiers

### Tier 0 — deterministic simulation (initial safe tier)

- Use deterministic protocol emulators and fabricated in-memory filesystems.
- Do not invoke a host shell, subprocess, arbitrary executable, or host filesystem path.
- Keep the current virtual terminal strictly allowlisted and read-only.
- Bound request sizes, command lengths, active sessions, execution time, memory, and event volume.
- Treat this as simulation, not a hardened sandbox. It is a safe development tier, not a production security boundary.

### Tier 1 — isolated decoy worker

Before any real process execution is considered, move untrusted protocol handling out of the privileged supervisor into a dedicated unprivileged worker boundary.

Required controls:

- Dedicated unprivileged UID/GID with no supplementary privileged groups.
- Separate mount, PID, IPC, UTS, and user namespaces where supported; network namespace with no default route and no egress.
- Read-only minimal runtime filesystem; private writable scratch space with strict size/inode limits.
- No host home directories, Docker/Podman sockets, SSH agents, D-Bus sockets, credentials, or arbitrary host mounts.
- Drop all Linux capabilities; no_new_privs; seccomp allowlist or equivalent syscall restrictions; deny ptrace and namespace creation from inside the worker.
- cgroup limits for CPU, memory, process count, and I/O; per-session concurrency and wall-clock limits.
- Restrict /proc and /sys views to the worker's own namespace; no host PID visibility.
- No direct access to the evidence file. Send bounded structured events through a one-way or capability-limited IPC channel to the evidence broker.
- Worker termination, timeout, or crash must not change backend routing or disable the independent enforcement policy.

For networked decoys, prefer a brokered connection model: the host-side listener/enforcement broker accepts or steers the connection and gives the worker only the already accepted client stream (or a narrow proxy channel). The worker must not be able to create arbitrary outbound connections. If a connected socket is passed to a worker, syscall and namespace policy must prevent creation of new sockets and tests must prove the worker cannot reach any other host or network endpoint.

The exact mechanism (systemd transient units, a rootless container runtime, or a purpose-built namespace launcher) must be selected only after verifying required kernel features, privilege assumptions, maintainability, and testability on supported Ubuntu versions. A container label alone is not proof of isolation.

### Tier 2 — disposable VM

Use a disposable virtual machine for higher-risk exploit observation or workloads that need a larger operating-system surface.

- Snapshot before each experiment and destroy or revert after use.
- Use a dedicated virtual network with no route to production or management networks.
- No shared host folders, clipboard, guest agent features, credentials, or device passthrough unless specifically reviewed.
- Apply CPU, memory, disk, and lifetime quotas.
- Collect telemetry through a narrow, authenticated channel; treat guest output as untrusted.
- Test the VM boundary and hypervisor configuration independently.

## Network and traffic boundary

- Protected services must not be reachable from any decoy worker or sandbox.
- Sandbox egress is denied by default. DNS, metadata endpoints, loopback-to-host access, link-local networks, RFC1918 networks, and IPv6 paths must be considered explicitly.
- A decoy worker may reply on its already-established client session but may not initiate a new connection to the client, backend, or another destination.
- Inbound traffic must be steered to the deception plane before protected application data is returned.
- Normal/allowed traffic and suspicious/deceptive traffic must have separately testable paths.
- No failure mode may fall back from an unhealthy decoy to the protected backend.

## Evidence boundary

- Workers emit structured, size-bounded events; they do not choose arbitrary file paths or write evidence directly.
- The supervisor/evidence broker validates event schema, source session, sequence, timestamps, and permitted fields.
- Credentials, private keys, cookies, authorization values, and unnecessary request bodies are excluded by default.
- Evidence persistence failure follows an explicit policy. A session must not silently continue as if fully monitored when required evidence cannot be committed.
- Every steering, sandbox-start, sandbox-stop, timeout, and containment action is itself auditable.

## Required release-gate tests

A sandbox implementation is not accepted until automated tests demonstrate:

1. Worker cannot read representative host files or user home directories.
2. Worker cannot inspect host processes, environment variables, credentials, sockets, or namespaces.
3. Worker cannot access Docker/Podman sockets, D-Bus, SSH agents, or host IPC endpoints.
4. Worker cannot create outbound IPv4 or IPv6 connections, resolve external names, or reach loopback services on the host.
5. Worker cannot reach protected service ports or internal networks.
6. Worker cannot create privileged namespaces, mount filesystems, ptrace another process, or regain capabilities.
7. CPU, memory, process count, disk, input size, session count, and lifetime limits are enforced.
8. A malformed request, parser crash, worker compromise simulation, or worker timeout cannot escape the boundary or expose a backend.
9. Evidence IPC cannot be used to overwrite files, inject arbitrary paths, or exhaust unbounded storage.
10. Supervisor restart, daemon crash, policy corruption, telemetry failure, and enforcement restart preserve fail-closed backend protection.
11. A legitimate flow continues to the configured real service while a policy-selected hostile flow reaches only the decoy.
12. The first response visible to a scanner is the selected decoy response, not a real service banner or application response.

Tests must run in disposable CI or dedicated test hosts. Do not run destructive escape tests against a developer workstation.

## Current implementation status\n\nThe declarative policy layer is implemented in `src/mirage/sandbox/policy.py`; the bounded event codec and sequence guard are in `src/mirage/sandbox/ipc.py`; and the Linux Unix-socket evidence broker is in `src/mirage/sandbox/worker_broker.py`. The broker validates worker peer UIDs, PIDs, bounded event frames, session registration, protocol binding, recent session replay, and sequence order before appending through the evidence store. It assigns a broker-owned profile ID and receipt timestamp. A separate owner-only control socket (`<worker-socket>.control`, mode 0600) accepts one-shot supervisor registrations containing the session UUID, protocol, accepted client peer IP/port, and expected worker UID/PID. The worker event socket accepts events only when the session was registered and the kernel-reported `SO_PEERCRED` UID/PID and protocol match. Registrations expire if the worker does not connect within the broker idle timeout and are consumed when the worker connection closes. Worker-claimed source addresses are ignored; evidence uses only the supervisor-registered peer metadata. The supervisor must obtain that metadata directly from the original accepted client socket and protect its control-socket access. The public helper `encode_supervisor_registration()` defines the registration frame. The CLI entry point is `mirage serve-worker-broker` and reports both socket paths. GitHub Actions run #417 passed the preceding broker milestone (282 tests, benchmark smoke test, and Ruff on Python 3.12–3.14); this registration change still requires fresh CI verification. The default same-UID development mode is not a security boundary: a compromised process running as the broker/supervisor UID can access the owner-only control socket. Use a distinct worker UID and explicit allowlist for a meaningful process-identity boundary. Current HTTP/SSH adapters are not connected to the broker, and no namespace launcher, cgroup manager, seccomp filter, disposable VM, or traffic-enforcement runtime has been implemented.\n\n## Implementation order

1. [x] Add a declarative sandbox policy model and validation tests; keep it separate from runtime enforcement.
2. [x] Build a bounded worker-supervisor IPC contract and private Unix-socket evidence broker with broker-owned evidence writes.
3. Connect HTTP/SSH decoy session handlers to the broker through supervised worker processes.
4. Select and prototype one Linux isolation mechanism on supported Ubuntu versions.
5. Add positive and negative namespace, filesystem, syscall, and network-boundary tests.
6. Add per-session lifecycle, resource quotas, crash handling, and cleanup.
7. Only after isolation passes, integrate the independent traffic enforcement and selective steering path.
8. Consider real process execution or disposable VMs only after separate threat review and escape testing.

## Explicit non-goals

- Do not run arbitrary commands from a remote client on the host.
- Do not connect decoy sessions to real production backends.
- Do not use a compromised scanner's machine as an execution target.
- Do not retaliate, scan third-party infrastructure, or attempt attribution beyond observable evidence.
- Do not build the tray or desktop dashboard during this isolation milestone.
