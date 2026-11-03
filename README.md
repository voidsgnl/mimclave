# MIRAGE

**Active Cyber Deception, Service Impersonation, Intrusion Containment & Threat Intelligence Platform**

MIRAGE is a Linux-first defensive platform designed to place controlled deception services in front of protected infrastructure. It presents configurable decoy services, records interactions, and contains activity inside isolated environments while keeping production services inaccessible from the decoy path.

> **Security invariant:** A compromise of a MIRAGE decoy must not provide a route to the protected host, its production services, credentials, or data.

## Project status

M1 configuration and read-only discovery is complete. M2 includes a pure HTTP response engine, a structured credential-conscious session-event model, and opt-in HTTP/HTTPS transports restricted to loopback addresses. HTTPS requires an explicitly provisioned server-side TLS context. CI verifies M2 on Python 3.12–3.14 (63 tests and Ruff passed); M3's hash-chained JSONL evidence store, idempotent event appends, and external checkpoint interface are CI-verified (82 tests and Ruff passed on Python 3.12–3.14). Verified export is implemented; a production remote checkpoint provider and automatic retention are not yet included. The transports do not forward traffic. No production traffic interception or sandbox execution is implemented. Do not deploy MIRAGE in front of production services.

## Core principles

- **Independent reality and deception:** Decoy identities and environments are configured independently of the real services they protect.
- **Protocol-port compatibility:** A decoy must speak the protocol expected on its exposed port (for example, HTTPS/TLS on 443). The real backend service does not need to match the decoy.
- **Isolation by default:** Decoys have no implicit access to host resources, production networks, or outbound destinations.
- **Evidence over assumptions:** Record observable activity and distinguish verified facts from attribution hypotheses.
- **Fail closed:** If enforcement, isolation, or policy state is uncertain, do not expose the protected service through the deception layer.
- **Defensive use only:** MIRAGE is for systems and networks the operator owns or is explicitly authorized to protect.

## Planned capabilities

1. Service and port discovery.
2. Independent decoy profiles and port-to-decoy mapping.
3. Protocol-aware service emulation.
4. Network interception and fail-closed containment.
5. Simulated command environments and fabricated filesystems.
6. Disposable, strongly isolated execution environments for controlled research.
7. Session recording, event timelines, and tamper-evident evidence.
8. Threat intelligence correlation and cautious attribution analysis.
9. Management API and operator dashboard.

See [Roadmap & Handoff](ROADMAP.md), [Architecture](docs/architecture.md), [Requirements](docs/requirements.md), [Configuration](docs/configuration.md), and [Threat Model](docs/threat-model.md).

## Development

Python 3.12+ is required. Install development dependencies with `python -m pip install -e '.[dev]'`, then run `pytest` and `ruff check .`. Use `mirage validate-config config/example.toml` to validate a configuration and `mirage discover` (or `python -m mirage discover`) to list locally visible TCP listeners and bound UDP sockets as JSON. UDP entries are bound-socket observations, not proof that an application-level service is responsive. Configuration validation and discovery are offline/read-only; network interception and sandbox execution are not implemented.

## Safety

MIRAGE must not be used to gain unauthorized access to third-party systems, execute commands on an attacker's device, or retaliate against observed sources. Network attribution is inherently uncertain: an IP address or fingerprint is not proof of a person's identity. Preserve evidence and use lawful investigative channels when real-world identification is required.

## License

License has not yet been selected.
