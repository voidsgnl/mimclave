# MIRAGE Threat Model

## Assets to protect

- Host operating system and kernel.
- Real services and their data.
- Credentials, keys, and configuration secrets.
- Internal network resources.
- Integrity and confidentiality of collected evidence.
- Availability of the protected host.

## Trust boundaries

1. **Untrusted client to host:** All inbound traffic is untrusted.
2. **Host enforcement to decoy listener:** Only explicitly configured traffic reaches decoys.
3. **Decoy to sandbox:** Treat every session and submitted input as hostile.
4. **Sandbox to host:** No implicit filesystem, process, credential, or network access.
5. **Telemetry to evidence store:** Collected data is untrusted input and must be safely parsed and integrity protected.
6. **Operator to management plane:** Administrative access requires authentication and audit logging.

## Threats

- Decoy process compromise.
- Container or VM escape.
- Sandbox-to-host or sandbox-to-LAN pivoting.
- Misconfigured port mapping exposing a real backend.
- Application crash causing fail-open routing.
- Malicious or malformed protocol input.
- Resource exhaustion and session flooding.
- Log injection, evidence tampering, and storage exhaustion.
- False attribution caused by VPNs, proxies, Tor, compromised intermediaries, or shared infrastructure.
- Operator misconfiguration or unauthorized management access.

## Required mitigations

- Keep production listeners off externally reachable interfaces where feasible.
- Enforce network separation with host-level controls independent of the MIRAGE process.
- Deny outbound sandbox networking by default.
- Do not mount host paths or pass host credentials into decoys.
- Avoid privileged containers; use syscall, capability, namespace, and resource restrictions.
- Use disposable VMs for higher-risk execution experiments.
- Fail closed and test crash/restart scenarios.
- Apply input validation, rate limits, quotas, and bounded evidence retention.
- Use append-only or tamper-evident evidence storage with access controls.
- Label attribution as evidence-based assessment, not proof of identity.

## Out of scope

MIRAGE does not attempt to access, execute commands on, persist on, or collect files from an attacker's personal device. It observes activity directed at MIRAGE-controlled services and records network-level metadata available to the protected system. Real-world identification must rely on lawful investigative processes and corroborated evidence.

## Security release gate

No feature that redirects production traffic or permits real process execution may be considered ready until its isolation properties, failure modes, and recovery procedures have been independently tested and documented.
