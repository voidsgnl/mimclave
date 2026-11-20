# MIRAGE

**Active Cyber Deception, Service Impersonation, Intrusion Containment & Threat Intelligence Platform**

MIRAGE is a Linux-first defensive platform designed to place controlled deception services in front of protected infrastructure. It presents configurable decoy services, records interactions, and contains activity inside isolated environments while keeping production services inaccessible from the decoy path.

> **Security invariant:** A compromise of a MIRAGE decoy must not provide a route to the protected host, its production services, credentials, or data.

## Project status

M1 configuration and read-only discovery, M2 safe HTTP/HTTPS simulation, and the M3 evidence pipeline are implemented. The first runnable local prototype now includes `mirage serve-http`: it starts a configured HTTP decoy on a loopback address, records each served request to the hash-chained JSONL evidence store before sending the response, and can verify that evidence with `mirage verify-evidence`. This is a local end-to-end demonstration, not production interception. The existing transports remain loopback-only; HTTPS requires an explicitly provisioned TLS context. M3 also includes segmented evidence storage, checkpoint-anchored rotation, verified export, non-destructive migration, an HTTPS checkpoint client, and a SQLite-backed checkpoint service. The checkpoint service has not been deployed or independently audited. Production traffic interception, isolated sandbox execution, and a management dashboard are not implemented. Do not deploy MIRAGE in front of production services.

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

Python 3.12+ is required. Install development dependencies with `python -m pip install -e '.[dev]'`, then run `pytest` and `ruff check .`.

### Run the local HTTP prototype

From the repository root, start the prototype with:

```bash
./start.sh
```

The script validates the configuration, creates a private `var/mirage/` evidence directory, and starts the decoy on `127.0.0.1:8080`. Set `MIRAGE_PORT` to use another local port, for example `MIRAGE_PORT=8081 ./start.sh`. If MIRAGE is not installed, the script asks permission to create a local `.venv` and install the project before continuing. On Ubuntu, if virtual-environment creation fails because the venv package is missing, install it with `sudo apt install python3-venv` and run the script again.

In another terminal, interact with the decoy:

```bash
curl -i http://127.0.0.1:8080/
curl -i http://127.0.0.1:8080/login
```

Stop the server with Ctrl+C, then verify the recorded chain:

```bash
./.venv/bin/mirage verify-evidence ./var/mirage/events.jsonl
```

The prototype binds only to a literal loopback IP. It does not forward requests to a protected service, alter firewall rules, expose a public listener, or execute submitted commands. Use the separate `config/prototype-http.toml` example rather than the illustrative HTTPS configuration. `mirage discover` lists locally visible TCP listeners and bound UDP sockets as JSON; UDP entries are bound-socket observations, not proof that an application-level service is responsive. The explicit `mirage migrate-evidence` command migrates a legacy log after an independently hosted HTTPS checkpoint service has been configured; its bearer token is read from `MIRAGE_CHECKPOINT_TOKEN`, never from a command-line argument. See [Evidence Segments](docs/evidence-segments.md) for migration and recovery instructions.

## Safety

MIRAGE must not be used to gain unauthorized access to third-party systems, execute commands on an attacker's device, or retaliate against observed sources. Network attribution is inherently uncertain: an IP address or fingerprint is not proof of a person's identity. Preserve evidence and use lawful investigative channels when real-world identification is required.

## License

License has not yet been selected.
