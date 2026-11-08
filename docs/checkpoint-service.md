# Independent MIRAGE Checkpoint Service

The repository includes a small SQLite-backed HTTP service implementing the
conditional checkpoint contract used by `HttpsCheckpointAnchor`. It is
intended to run on a **separate, independently administered host** from the
MIRAGE evidence store.

Running this service on the evidence host does not provide independent
protection. The service host, database, credentials, backups, and administrative
access must remain outside the evidence host's trust boundary.

## What it provides

- A single checkpoint resource with authenticated `GET` and conditional `PUT`.
- Strong ETags and atomic compare-and-set updates.
- Strictly increasing checkpoint generations and record counts.
- SQLite transactions using `BEGIN IMMEDIATE` and `synchronous=FULL`.
- An append-only, hash-chained `checkpoint_history` table; update/delete triggers reject ordinary mutation, and every read/write verifies the history chain and current-row consistency.
- A private database directory (`0700`) and database file (`0600`).
- A loopback-only HTTP listener; it does not expose a public plaintext listener.
- No endpoint for deleting or resetting checkpoint history.
- No request-header logging; bearer tokens are not written to service logs.

The service rejects malformed or duplicate JSON keys, oversized request bodies,
missing conditional headers, stale ETags, generation rollback, and record-count
rollback. A failed conditional update returns HTTP 412, which the existing
HTTPS client maps to `CheckpointConflictError`.

## Install and configure on the separate host

Install MIRAGE on the checkpoint host, then create a private service directory
and a high-entropy token:

```bash
sudo useradd --system --home-dir /var/lib/mirage-checkpoint --create-home --shell /usr/sbin/nologin mirage-checkpoint
sudo install -d -m 0700 -o mirage-checkpoint -g mirage-checkpoint /var/lib/mirage-checkpoint
openssl rand -hex 32
```

Use the generated token in a root-readable environment file such as
`/etc/mirage-checkpoint.env`:

```ini
MIRAGE_CHECKPOINT_TOKEN=replace-with-generated-64-character-token
MIRAGE_CHECKPOINT_DB=/var/lib/mirage-checkpoint/checkpoint.sqlite3
MIRAGE_CHECKPOINT_HOST=127.0.0.1
MIRAGE_CHECKPOINT_PORT=8080
MIRAGE_CHECKPOINT_PATH=/v1/mirage/checkpoint
```

Protect the file:

```bash
sudo chown root:root /etc/mirage-checkpoint.env
sudo chmod 0600 /etc/mirage-checkpoint.env
```

The service requires a bearer token of at least 32 characters. Do not commit the
token, place it in command-line arguments, or reuse it for unrelated services.

Install the supplied systemd unit. If MIRAGE is installed in a virtual
environment, edit `ExecStart` in the unit to point to that environment's
`mirage-checkpoint-server` executable:

```bash
sudo install -m 0644 deploy/mirage-checkpoint.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now mirage-checkpoint.service
sudo systemctl status mirage-checkpoint.service
```

The unit runs as the dedicated unprivileged account, uses a restrictive umask,
and applies systemd filesystem and privilege protections. Keep the
`EnvironmentFile` owned by root with mode `0600`.

## Put HTTPS in front of the loopback listener

Use a TLS-terminating reverse proxy on the checkpoint host. For Caddy, copy the supplied example to the Caddy configuration location and
replace the example hostname with the checkpoint host's DNS name:

```caddyfile
anchor.example.net {
    reverse_proxy 127.0.0.1:8080
}
```

Caddy obtains and renews the HTTPS certificate. Restrict inbound firewall
access to HTTPS on the proxy; do not expose port 8080. The public endpoint
configured in the evidence host's `HttpsCheckpointAnchor` and migration CLI
must be:

```text
https://anchor.example.net/v1/mirage/checkpoint
```

The proxy and service host should have their own access controls, monitoring,
patching, and backup policy.

## Configure the evidence host

Load the same bearer token into the evidence host's secret manager or protected
environment. Then configure the HTTPS client or run the migration CLI:

```bash
mirage migrate-evidence \
  /var/lib/mirage/evidence.jsonl \
  /var/lib/mirage/evidence-segmented \
  --checkpoint-url https://anchor.example.net/v1/mirage/checkpoint \
  --max-segment-bytes 8388608 \
  --hard-max-segment-bytes 16777216
```

The CLI reads `MIRAGE_CHECKPOINT_TOKEN` from the environment. It never accepts
the bearer token as an argument or prints it.

## Operational requirements and limitations

- Keep the checkpoint host and its backups independent of the evidence host.
- Back up the SQLite database using a consistent SQLite backup procedure.
  Restoring an older database can roll the anchor backward; treat restoration
  as a security incident and reconcile it against preserved evidence before
  resuming writes.
- Monitor disk space, service availability, TLS certificate renewal, and failed
  conditional writes.
- Rotate the bearer token through a planned coordinated change on both hosts.
- The service keeps an append-only, hash-chained history in SQLite, but the
  history is still on the checkpoint host's storage. Export or back it up
  independently so a privileged attacker on that host cannot silently rewrite
  both the database and its history.
- The service has not been deployed or independently audited. CI tests verify
  its API contract, conditional-write serialization, history integrity, and
  local persistence; they do not prove host independence, backup correctness,
  operational security, or production readiness.
