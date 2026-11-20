# MIRAGE

**Active Cyber Deception, Service Impersonation, Intrusion Containment & Threat Intelligence Platform**

MIRAGE is a Linux-first defensive monitoring and adaptive-deception platform intended to run continuously as a system-level service. It observes network activity in real time, preserves normal service for legitimate traffic, and selectively steers suspicious traffic to coherent fabricated services inside isolated sandboxes before protected application data is disclosed. Detection and containment are separate decisions: MIRAGE intervenes only when an explicit policy threshold is met. A future system-tray client and full desktop dashboard will provide status, configuration, and investigation views, but neither is required for the service to operate.

> **Security invariant:** A compromise of a MIRAGE decoy must not provide a route to the protected host, its production services, credentials, or data.

## Project status

M1 configuration and read-only discovery, M2 safe HTTP/HTTPS simulation, and the M3 evidence pipeline are implemented. The runnable local prototype includes `mirage serve-http` and an experimental `mirage serve-ssh` adapter for the in-memory terminal. Both are restricted to loopback and record interactions to hash-chained JSONL evidence before returning simulated output. SSH support is optional and is not production-ready. The existing transports remain loopback-only; HTTPS requires an explicitly provisioned TLS context. M3 also includes segmented evidence storage, checkpoint-anchored rotation, verified export, non-destructive migration, an HTTPS checkpoint client, and a SQLite-backed checkpoint service. The checkpoint service has not been deployed or independently audited. Production traffic interception, selective steering, hardened sandbox execution, independent fail-closed enforcement, and the system daemon lifecycle are not implemented. A declarative sandbox policy model, bounded worker-event message codec, and private Unix-socket evidence broker now exist. The broker validates worker UIDs and events before writing to the hash-chained evidence store. No isolated worker process or sandbox runtime is connected yet. The tray and full desktop dashboard are intentionally deferred until the core runtime is working and security-tested. Do not deploy MIRAGE in front of production services.

## Intended operating model\n\nMIRAGE is designed to monitor continuously in the background. Ordinary traffic should continue to its protected service under policy; traffic classified for deception should be diverted to a separate, fabricated environment. All attacker-controlled interaction remains sandboxed. The monitoring daemon must continue working when the tray or dashboard is closed. See [Runtime and Adaptive Deception Model](docs/runtime-model.md) for the design and security release gates.\n\n## Core principles

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
5. Simulated command environments and fabricated filesystems (initial local interpreter implemented).
6. Disposable, strongly isolated execution environments for controlled research.
7. Session recording, event timelines, and tamper-evident evidence.
8. Threat intelligence correlation and cautious attribution analysis.
9. Management API and operator dashboard.

See [Roadmap & Handoff](ROADMAP.md), [Architecture](docs/architecture.md), [Requirements](docs/requirements.md), [Configuration](docs/configuration.md), [Threat Model](docs/threat-model.md), and [SSH Decoy](docs/ssh-decoy.md).

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

### Try the virtual terminal

Run the isolated, in-memory Linux-like command interpreter:

```bash
./.venv/bin/mirage simulate-terminal
```

Try `help`, `whoami`, `hostname`, `pwd`, `ls`, `cd /home/deploy`, `cat README.txt`, `cat /etc/passwd`, or `ps aux`. Type `exit` to leave. The files, users, processes, and host identity are fabricated examples.

**This is not a real shell.** Only a small allowlist of read-only commands exists. MIRAGE does not call a shell or subprocess, access the host filesystem, or make network connections. Pipes, redirects, command chaining, expansions, and path traversal are rejected. Unknown commands are not executed. This local interpreter is also available through the experimental loopback-only SSH adapter described below.


### Try the experimental SSH decoy

Install the optional SSH dependency:

```bash
./.venv/bin/python -m pip install -e '.[ssh]'
```

Create a dedicated host key (do not reuse your personal or system SSH keys):

```bash
install -d -m 700 var/mirage/keys
ssh-keygen -t ed25519 -N '' -f var/mirage/keys/mirage_test_host_ed25519
chmod 600 var/mirage/keys/mirage_test_host_ed25519
```

Start the SSH decoy. It binds only to loopback:

```bash
./.venv/bin/mirage serve-ssh \
  --host 127.0.0.1 \
  --port 2222 \
  --host-key var/mirage/keys/mirage_test_host_ed25519 \
  --evidence var/mirage/ssh-events.jsonl
```

Connect from another terminal:

```bash
ssh -p 2222 \
  -o UserKnownHostsFile=var/mirage/ssh_known_hosts \
  -o StrictHostKeyChecking=accept-new \
  visitor@127.0.0.1
```

Try `whoami`, `pwd`, `ls`, `cat /etc/passwd`, and `cd /home/deploy`.
Verify interactions after stopping the server:

```bash
./.venv/bin/mirage verify-evidence var/mirage/ssh-events.jsonl
./.venv/bin/mirage inspect-sessions var/mirage/ssh-events.jsonl
```

The SSH adapter accepts sessions without client authentication, never stores
passwords or full command lines, and runs commands only in the fabricated
interpreter. Port forwarding, SFTP, agent forwarding, and X11 are disabled.
It is an experimental local prototype, not an isolated sandbox or a public
honeypot. **Do not expose it beyond loopback.** See [SSH Decoy](docs/ssh-decoy.md)
for its limits and security boundaries.


### Sandbox worker evidence broker (IPC prototype)

The worker evidence broker is a separate process boundary for future isolated decoy workers. It accepts bounded newline-delimited event messages over a private Linux Unix-domain socket, checks peer credentials with `SO_PEERCRED`, validates one session per connection and strictly increasing event sequence numbers, then writes accepted events through the existing hash-chained evidence store. Workers do not receive an evidence-file path or direct write access.

Create a private socket directory and start the broker:

```bash
install -d -m 700 var/mirage/worker

./.venv/bin/mirage serve-worker-broker \
  --socket var/mirage/worker/broker.sock \
  --evidence var/mirage/worker-events.jsonl
```

The default socket is mode `0600` and accepts connections only from the broker's effective UID. A separately provisioned worker group can use `--socket-gid` with one or more explicit `--allowed-uid` values; in that mode the parent directory must be owned by the broker UID, match the configured group, and use owner `rwx`, group execute-only, and no world permissions. The broker refuses to replace an active socket or an unexpected filesystem object.

This milestone provides a usable broker endpoint and message contract, **not an isolated worker**. No current HTTP/SSH transport sends events through this broker yet; those prototypes still append directly to their evidence store. The default same-UID development mode is not a security boundary against compromise of that UID. Do not treat this IPC service as proof of sandbox isolation or expose it on a network socket.

### Inspect recorded activity

After generating some requests, inspect the verified evidence log:

```bash
./.venv/bin/mirage inspect-sessions ./var/mirage/events.jsonl
```

Use JSON output for scripts or further analysis:

```bash
./.venv/bin/mirage inspect-sessions ./var/mirage/events.jsonl --json
```

The default inactivity window is 30 minutes; change it with `--idle-timeout 600` (seconds). MIRAGE verifies the complete evidence chain before producing a report. Activity clusters are heuristic groupings by source IP, decoy profile, and inactivity—not authenticated user sessions. Shared NAT or proxy addresses can combine multiple people. Rules flag observable patterns such as sensitive-path probes, repeated 404 paths, repeated routes, and high request rates; they are triage signals, not proof of malicious intent. Request bodies, query strings, cookies, authorization headers, and User-Agent values are not included in the report.

The prototype binds only to a literal loopback IP. It does not forward requests to a protected service, alter firewall rules, expose a public listener, or execute submitted commands. Use the separate `config/prototype-http.toml` example rather than the illustrative HTTPS configuration. `mirage discover` lists locally visible TCP listeners and bound UDP sockets as JSON; UDP entries are bound-socket observations, not proof that an application-level service is responsive. The explicit `mirage migrate-evidence` command migrates a legacy log after an independently hosted HTTPS checkpoint service has been configured; its bearer token is read from `MIRAGE_CHECKPOINT_TOKEN`, never from a command-line argument. See [Evidence Segments](docs/evidence-segments.md) for migration and recovery instructions.

## Safety

MIRAGE must not be used to gain unauthorized access to third-party systems, execute commands on an attacker's device, or retaliate against observed sources. Network attribution is inherently uncertain: an IP address or fingerprint is not proof of a person's identity. Preserve evidence and use lawful investigative channels when real-world identification is required.

## License

License has not yet been selected.
