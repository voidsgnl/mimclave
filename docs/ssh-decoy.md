# SSH Virtual-Terminal Decoy

## Status and scope

MIMCLAVE includes an experimental SSH transport adapter for its deterministic,
in-memory virtual terminal. It is intended for local integration testing only.
The listener refuses non-loopback addresses and must not be exposed to a LAN or
the public internet.

The SSH protocol implementation is provided by the optional
[AsyncSSH](https://asyncssh.readthedocs.io/) dependency. MIMCLAVE does not
implement cryptography or the SSH wire protocol itself.

## Security properties

- Each SSH session receives a new `VirtualTerminal` instance. Working-directory
  changes and other session state are not shared.
- Commands are passed only to the existing allowlisted virtual interpreter.
  No host shell, subprocess, host filesystem, production service, or network
  forwarding is used.
- The server requests no password or client credential. It does not collect or
  store passwords, private keys, environment variables, or full command lines.
- Evidence records contain the event type, per-session ID and sequence,
  timestamp, profile, source address, and normalized command name only.
  Arguments and command text are deliberately omitted.
- Each command event is appended and fsynced before its simulated output is
  returned. If evidence persistence fails, the SSH channel exits without
  returning command output.
- TCP listeners are loopback-only. The default is `127.0.0.1:2222`.
- Connection and active-session counts, login time, command length, command
  count, per-command idle time, and SSH channel window are bounded.
- TCP forwarding, remote forwarding, UNIX forwarding, agent forwarding, X11,
  and SSH subsystems such as SFTP are disabled.
- Shutdown stops the listener and closes tracked active SSH connections.

This is an unauthenticated deception service: any client which can reach the
loopback listener can open a simulated session without supplying credentials.
It is not an authentication service and must not be used to protect real data.

## Install and prepare a dedicated host key

Install the optional dependency:

```bash
python -m pip install -e '.[ssh]'
```

Create a dedicated key for this test service. Do not point MIMCLAVE at your
personal `~/.ssh/id_*` key or reuse the host's real SSH server key:

```bash
install -d -m 700 var/mimclave/keys
ssh-keygen -t ed25519 -N '' -f var/mimclave/keys/mimclave_test_host_ed25519
chmod 600 var/mimclave/keys/mimclave_test_host_ed25519
```

The private key is local runtime material and must never be committed. The
repository ignores `/var/`.

## Start the local SSH decoy

```bash
./.venv/bin/mimclave serve-ssh \
  --host 127.0.0.1 \
  --port 2222 \
  --host-key var/mimclave/keys/mimclave_test_host_ed25519 \
  --evidence var/mimclave/ssh-events.jsonl
```

In another terminal, connect using the dedicated local known-hosts file:

```bash
ssh -p 2222 \
  -o UserKnownHostsFile=var/mimclave/ssh_known_hosts \
  -o StrictHostKeyChecking=accept-new \
  visitor@127.0.0.1
```

Try safe simulated commands such as `whoami`, `pwd`, `ls`,
`cat /etc/passwd`, and `cd /home/deploy`. Type `exit` to disconnect.

Verify the interaction evidence after stopping the server:

```bash
./.venv/bin/mimclave verify-evidence var/mimclave/ssh-events.jsonl
./.venv/bin/mimclave inspect-sessions var/mimclave/ssh-events.jsonl
```

## Current limitations

- This is a local prototype, not a production honeypot or an isolated sandbox.
- Authentication is intentionally disabled; the service accepts sessions
  without validating a client identity.
- The SSH host key must be provisioned by the operator. MIMCLAVE does not
  generate it or alter SSH configuration.
- Command output is a deterministic simulation. There is no real operating
  system behind the session.
- The event schema records normalized command names, not full command lines,
  command arguments, terminal keystrokes, or passwords.
- No production traffic interception, firewall enforcement, containment, or
  remote public listener is implemented.
- Do not expose this service beyond loopback. A future deployment requires a
  separately threat-modelled isolation boundary, default-deny egress, stronger
  connection-level resource controls, and independent fail-closed enforcement.
