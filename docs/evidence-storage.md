# Evidence Storage — M3 Design

## Scope

M3 begins with a local, append-only JSON Lines evidence store for structured MIRAGE events. It is intended for development and controlled deployments on Linux. It is not yet a production evidence vault, remote collector, SIEM integration, or substitute for independent network enforcement.

## Record format and integrity

Each line is a canonical JSON envelope containing:
- `schema_version`: integer format version.
- `previous_hash`: SHA-256 hash of the previous envelope, or 64 zeroes for the first record.
- `event`: the structured `SessionEvent` payload.
- `record_hash`: SHA-256 of the canonical JSON bytes for the envelope fields excluding `record_hash`.

Canonical JSON uses sorted keys, compact separators, UTF-8, and rejects non-finite numbers. Each record ends with exactly one newline. Verification walks the complete file, validates the schema and previous-hash link, recomputes every record hash, and rejects malformed or incomplete lines. Appending first verifies the existing chain while holding an exclusive OS file lock, then writes the complete record and calls `fsync`.

This is tamper-evident, not tamper-proof. An actor who can rewrite the entire file can recompute the chain. Detecting whole-file replacement or truncation requires an independently retained checkpoint (for example, a signed or remotely stored head hash); external anchoring is not part of the first implementation.

## Failure semantics

- Evidence append is synchronous and durable-before-return: the event sink must not report success until the record is written and `fsync` completes.
- If validation, locking, writing, or `fsync` fails, append raises an explicit storage error. The transport must not send a decoy response when its required event sink fails.
- A malformed, truncated, or hash-invalid existing log is never silently repaired or appended to. Operators must preserve the file and investigate.
- No background queue is introduced in this stage. This avoids acknowledging an event that has not reached durable storage. Bounded asynchronous batching/backpressure can be designed later if measured throughput requires it.

## File safety and permissions

- Create evidence files with mode `0600`; reject existing files with group/other permissions, symlinks, non-regular files, or multiple hard links.
- Use an OS-level exclusive file lock for append and a shared lock for verification.
- Do not mount the evidence directory into any future untrusted decoy execution environment.
- Do not store request bodies, passwords, cookies, authorization headers, or query strings. The store serializes only the existing `SessionEvent` schema.
- The initial store has no automatic retention deletion. Retention/export policy must preserve chain continuity and account for external checkpoints before deletion is introduced.

## Ordering and concurrency

The hash chain establishes one total append order for the file. Per-session sequence numbers remain the event-order authority within a session; timestamps are descriptive UTC observations and are not used to reorder records. The initial implementation validates the complete chain before each append, prioritizing correctness over large-file write throughput. A checkpoint/index design is required before optimizing this path for high-volume logs.

## Initial M3 exit criteria

- Append and fsync one event before acknowledging success.
- Verify the complete hash chain and reject tampering, malformed JSON, and incomplete trailing records.
- Serialize concurrent appenders without interleaving records.
- Fail closed when storage is unavailable or corrupt.
- Test file permissions, symlink/hard-link rejection, concurrency, tampering, and transport integration.
- Document limitations: whole-file rewrite/truncation requires external head-hash anchoring to detect.


## Implementation status
The first implementation is in `src/mirage/telemetry/store.py` as `JsonlEvidenceStore`. It serializes only the existing `SessionEvent` fields, verifies the entire existing chain before each append, serializes appenders with `flock`, writes with append semantics, and calls `fsync` before returning an `EvidenceReceipt`. The HTTP transport can use `store.append` directly as its required event sink. The initial tests are in `tests/test_evidence_store.py` and `tests/test_http_transport.py`. CI run #116 passed 73 tests and Ruff on Python 3.12–3.14.


## Idempotency and retry semantics

The caller must retain and reuse the same immutable `SessionEvent` (especially its `event_id`) when retrying an append whose outcome is uncertain. Under the exclusive file lock, append verifies the complete chain and searches for that event ID before writing:

- If the ID is absent, the event is appended and fsynced.
- If the ID exists with an identical serialized event payload, append returns the original receipt without writing a second record. This makes a retry safe after a caller lost the original success response or an fsync outcome was ambiguous but the complete record is present.
- If the ID exists with a different payload, append raises `EvidenceEventConflictError`; it never overwrites or silently accepts the conflicting event.
- A valid hash chain containing duplicate event IDs is rejected as an integrity error.

This is idempotent append, not exactly-once delivery across arbitrary process/storage failures. If a crash leaves a partial trailing line, verification rejects the log and append stops; do not truncate or auto-repair evidence. Preserve the file for operator investigation. A retry cannot safely infer whether a partial write represented a committed event.


## External checkpoints

The store exposes `publish_checkpoint(anchor)` and `verify_checkpoint(anchor)` using the contract in `mirage.telemetry.checkpoints`. A checkpoint commits to a monotonically increasing generation, record count, and chain head hash. Publication is serialized against appends with the evidence file lock and uses the anchor's atomic compare-and-set operation.

The anchor is an injected `CheckpointAnchor` implementation. Its durable state must be stored outside the evidence file's trust boundary (for example, a separately administered remote service or independently protected database). The repository currently defines the interface and tests it with an in-memory test double; it does not yet ship a production remote anchor implementation. CI run #135 passed 79 tests and Ruff on Python 3.12–3.14. A local sidecar file on the same host is not an independent anchor.

Verification checks the entire local chain and confirms that the record at the externally committed count has the anchored hash. It rejects a log shorter than the checkpoint or a replacement whose prefix differs. A log may contain additional valid records after the last checkpoint; those records are unanchored until the next successful publication. External implementations must enforce monotonic generations and durable compare-and-set; a last-write-wins store is not sufficient.


## Verified export and retention boundary

`export_verified(destination, anchor=...)` creates a new file with mode `0600`, refuses to overwrite an existing destination, verifies the complete source chain, optionally verifies its externally anchored prefix, copies the original JSONL bytes, fsyncs the exported file, and fsyncs the destination directory. The source log is held under a shared lock for the operation and is never modified. The export is therefore a verified copy, not a retention deletion or rotation operation.

If export writing or syncing fails, a partial destination may remain; preserve and inspect it rather than treating it as a valid export. The destination can be independently checked with `JsonlEvidenceStore(destination).verify()`. If an external checkpoint was used, retain the checkpoint receipt from the anchor as separate provenance; the JSONL file alone does not contain the external anchor's trust.

No automatic deletion, pruning, rotation, or retention scheduler is implemented. Do not delete the source merely because an export call returned: independently verify the exported file, preserve its checkpoint provenance in the independent anchor, and follow an operator-approved retention policy. Current hash chains begin at the genesis hash, so removing an earlier prefix would break verification; segmented retention needs a separately specified segment manifest and checkpoint handoff. CI run #142 passed 82 tests and Ruff on Python 3.12–3.14.


## Throughput measurement

Run `python scripts/benchmark_evidence_store.py --events 100` from the repository root to measure synchronous append throughput and full-chain verification on the target filesystem and hardware. The benchmark uses a temporary directory and synthetic metadata-only events; it does not touch production evidence. CI run #151 passed a 10-event smoke test on Python 3.12–3.14 to ensure the benchmark remains executable, but CI timing is not a performance baseline. Record measurements on representative Linux storage before deciding whether a bounded asynchronous queue or indexed/checkpointed verification is justified.


## HTTPS checkpoint client and remote service contract

`mirage.telemetry.https_anchor.HttpsCheckpointAnchor` is the production-facing client adapter for an independently hosted checkpoint service. It accepts an exact HTTPS resource URL and a bearer token. It uses the platform's default certificate-verifying TLS context, refuses redirects, applies a request timeout, bounds response bodies to 4096 bytes, and never places credentials in the URL. The token should be loaded from a secret manager or protected environment at deployment; do not commit it, put it in TOML checked into source control, or log request headers.

The remote service must implement this conditional resource contract:

- `GET <resource>`: return HTTP 200 with JSON `{"generation":N,"record_count":N,"head_hash":"<64 lowercase hex chars>"}` and a **strong** ETag. Return 404 only when no checkpoint exists.
- `PUT <resource>`: accept the same JSON shape. For initial creation require `If-None-Match: *`; for updates require `If-Match: <previous strong ETag>`. Return HTTP 200 or 201 with the committed checkpoint JSON and a new strong ETag.
- Return HTTP 409 or 412 when the conditional precondition fails. The client maps these to `CheckpointConflictError`.
- The service must atomically enforce the ETag precondition, require generation 1 for initial creation and exactly previous generation + 1 for updates, durably commit before replying, and reject rollback or arbitrary replacement. A database transaction with a unique singleton resource and compare-and-swap update is a suitable server-side implementation.
- All other redirects, unexpected statuses, malformed responses, missing/weak ETags, oversized bodies, TLS failures, and network errors fail as `CheckpointError`; certificate verification is not disabled.

Example construction (the application must obtain the secret from its deployment secret manager):

```python
from mirage.telemetry.https_anchor import HttpsCheckpointAnchor

anchor = HttpsCheckpointAnchor(
    "https://evidence-anchor.example.net/v1/mirage/checkpoint",
    bearer_token=load_secret("MIRAGE_CHECKPOINT_TOKEN"),
)
store.publish_checkpoint(anchor)
```

The repository now includes the HTTPS client adapter, not a hosted checkpoint server. It becomes an independent anchor only when deployed against a separately administered service whose storage, credentials, backups, and operator access are outside the evidence host's trust boundary. Do not point it at a service hosted on the same machine and describe that as independent protection. A timeout after a remote commit is ambiguous; retrying `publish_checkpoint` is safe because it reads the committed checkpoint and returns it when the local head already matches.
