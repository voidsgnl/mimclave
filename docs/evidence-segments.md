# Evidence Segments, Rotation, and Retention — M3 Design

**Status:** The legacy `JsonlEvidenceStore` remains unchanged; `SegmentedEvidenceStore` and an explicit, non-destructive legacy-log migration API are implemented in `src/mirage/telemetry/segmented.py`. Migration verifies and externally anchors the complete source head, copies original record bytes unchanged into sealed segment 1, creates an empty active segment 2, verifies the staged store, and atomically publishes the destination. The source is never moved or deleted. GitHub Actions run #238 passed 130 tests, the evidence benchmark smoke test, and Ruff on Python 3.12–3.14. Targeted crash tests now cover initialization, durable append acknowledgement, partial writes, rotation, retirement, and migration publication; exhaustive filesystem-boundary coverage and target-hardware benchmarking remain outstanding.

## Problem

The current store is one JSONL file whose hash chain starts at the genesis hash. This has two consequences:

1. **Retention is impossible without breaking verification.** Removing any prefix invalidates the chain, so nothing can ever be deleted.
2. **Append cost grows without bound.** Every append reads and re-verifies the entire file under an exclusive lock.

Rotation and retention must not weaken the existing guarantees: tamper-evidence, fsync-before-acknowledgement, fail-closed behaviour, and no silent repair of evidence.

## Goals and non-goals

**Goals**
- Bound the size of any single evidence file and the cost of an append.
- Allow old evidence to be retired only after it has been independently preserved and externally anchored.
- Keep one continuous, verifiable hash chain across all segments.
- Keep the existing `CheckpointAnchor` contract and `HttpsCheckpointAnchor` client unchanged.
- Make every rotation and retirement step crash-safe and resumable.

**Non-goals**
- Automatic or scheduled deletion. Retirement is always an explicit, operator-approved action.
- Compression, encryption at rest, or remote shipping of segments.
- A hosted checkpoint service (still a separate deployment dependency).
- Replacing the anchor with something that makes the evidence host trusted.

## Layout

Segmented evidence lives in a private directory (mode `0700`):

```
evidence/
  manifest.jsonl            # hash-chained log of segment lifecycle entries
  segment-00000001.jsonl    # sealed, read-only (0400)
  segment-00000002.jsonl    # sealed, read-only (0400)
  segment-00000003.jsonl    # active, append-only (0600)
```

All files are created with `O_EXCL | O_NOFOLLOW`, mode `0600` (sealed segments are tightened to `0400`). The existing symlink, hard-link, non-regular-file, and permission rejections apply to every file in the directory, and any unexpected file matching the segment name pattern that is not in the manifest is an integrity error (it is never adopted automatically). The directory must not be mounted into any untrusted decoy execution environment.

## One continuous chain

Segment record envelopes are unchanged (`schema_version` 1, `previous_hash`, `event`, `record_hash`). The only difference is the link of a segment's first record:

- Segment 1: `previous_hash` is the genesis hash (64 zeroes), exactly like today's single file. A legacy single-file log is therefore a valid segment 1 as-is.
- Segment N > 1: the first record's `previous_hash` is the `record_hash` of the last record of segment N−1.

Record numbers are **global and cumulative**: segment N's first record has number `last_record_number(N−1) + 1`. This keeps `EvidenceCheckpoint.record_count` and `head_hash` meaning exactly what they mean today (the global record count and the hash of that record), so the anchor contract and client need no change.

A segment is verified from a starting `(record_number, previous_hash)` supplied by the manifest instead of always from genesis. Per-event idempotency (`event_id` uniqueness) is enforced across all retained segments; evidence for an event ID inside a retired segment can no longer be checked, which is documented as a limitation below.

## Manifest

`manifest.jsonl` is an append-only, hash-chained JSONL file using the same canonical JSON rules as evidence records. Each line is an envelope with `schema_version`, `previous_manifest_hash` (genesis for the first entry), `entry`, and `entry_hash` (SHA-256 of the canonical envelope without `entry_hash`). Entry types:

| Entry | Fields |
|---|---|
| `segment_opened` | `segment_id`, `file_name`, `first_record_number`, `start_previous_hash`, `opened_at` |
| `segment_sealed` | `segment_id`, `record_count`, `last_record_number`, `last_hash`, `file_size`, `file_sha256`, `checkpoint_generation`, `sealed_at` |
| `segment_retired` | `segment_id`, `retired_at`, `last_record_number`, `last_hash`, `export_sha256`, `checkpoint_generation`, `approval_id` |

Rules enforced by manifest verification:
- Segment IDs are contiguous starting at 1; at most one segment is open (active) and it is always the newest.
- `start_previous_hash` of segment N equals `last_hash` of segment N−1 (or genesis for segment 1).
- `first_record_number` of segment N equals `last_record_number` of N−1 plus one.
- Segments are retired strictly oldest-first, so the retained range is always contiguous.
- `segment_retired` retains `last_record_number` and `last_hash`, so cumulative numbering and the link into the first retained segment remain verifiable after the file is gone.

The manifest is tamper-evident but, like the evidence file, rewritable by an actor who controls the directory. It is made trustworthy by the same mechanism as the evidence: the external checkpoint (see below), plus cross-checks against the evidence bytes.

## Locking

All operations lock `manifest.jsonl` (exclusive for append, rotation, retirement, and checkpoint publication; shared for verification and export). Segment files are only appended to while the manifest lock is held. This preserves the existing guarantee that concurrent appenders serialize into one valid chain.

## Append path

Under the exclusive manifest lock, append:
1. Verifies the manifest chain and its consistency with the directory listing.
2. Verifies the **active segment** from its manifest start point and checks idempotency against the retained event index.
3. By default (`verify_sealed_on_append=True`) also re-verifies every retained sealed segment against its recorded `file_size` and `file_sha256` and its chain links. This preserves today's guarantee that every append follows a full verification of retained evidence.
4. Writes the record, calls `fsync`, and returns the receipt.

Sealed segments are immutable and are `0400`. Setting `verify_sealed_on_append=False` turns per-append cost from O(retained log) into O(active segment); sealed segments are then covered by `file_sha256` in the manifest, by an explicit `verify_all()` operation that walks every retained segment and every cross-segment link, and by export and checkpoint verification. Tampering with a sealed segment is then detected by those operations rather than on the next append. This switch is an explicit operator decision (see Decisions), never a silent default.

## Rotation

Rotation is triggered under the exclusive lock when the active segment reaches a configured soft limit (`max_segment_bytes` and/or `max_segment_records`). A rotation must complete in this order:

1. Verify the active segment and the manifest.
2. Publish an external checkpoint for the current head via the existing `publish_checkpoint` logic. The checkpoint's `record_count` and `head_hash` must equal the segment's final record number and hash. **If publication fails, the segment is not sealed.**
3. Append `segment_sealed` (including `file_size`, `file_sha256`, and the checkpoint generation) to the manifest and `fsync`.
4. `chmod` the segment to `0400` and `fsync` it and the directory.
5. Append the `segment_opened` successor intent to the manifest and `fsync`; then create the empty next segment (`O_EXCL`, `0600`), `fsync` the file, and `fsync` the directory.

Every sealed segment boundary is therefore anchored externally at the moment it is sealed.

**Failure policy.** A rotation failure (for example an anchor outage) must not silently stop evidence collection, but it must not allow unbounded growth either. Two limits apply:
- Soft limit: attempt rotation; on failure keep appending to the current segment and report the failure to the operator.
- Hard limit (`hard_max_segment_bytes`, which must be greater than the soft limit): append fails closed with an explicit storage error. Because the transport sends no decoy response when its event sink fails, an extended anchor outage eventually stops the decoy from answering rather than losing evidence. This is deliberate and must be documented for operators.

**Crash recovery.** On open, reconcile manifest and directory:
- `segment_sealed` with no successor `segment_opened`: append the successor-open intent first, then create the next empty segment (idempotently).
- `segment_opened` whose file does not exist or is empty: create or accept the empty file.
- A segment file present but absent from the manifest, a missing sealed segment that is not retired, a hash or size mismatch against `segment_sealed`, or a non-empty file for a segment the manifest has not opened: **integrity error**. Preserve everything and stop; never truncate, adopt, or repair.

## Retention (retirement)

Retirement is an explicit operator action, for example `retire_oldest_segment(export_destination, anchor, approval_id)`. It never runs on a timer. Preconditions, all checked while the exclusive lock is held and all segment bytes are still present:

1. The target is the oldest retained segment and is sealed.
2. `export_verified` has produced a copy **outside** the evidence directory, and an independent re-verification of that copy (`verify()` plus a SHA-256 comparison against `file_sha256`) succeeds. The export hash is recorded as `export_sha256`.
3. The latest external checkpoint verifies against the live retained chain (`verify_checkpoint`), and its generation is not older than the generation recorded when the segment was sealed.
4. An operator-supplied `approval_id` is recorded. An optional minimum age (`min_retention_days`) may be enforced.

Steps, in order:
1. Append `segment_retired` to the manifest and `fsync`. This is the commit point.
2. Unlink the segment file and `fsync` the directory.

**Crash between 1 and 2:** the manifest says retired but the file still exists. On open, a retired segment's file is allowed to remain only if its SHA-256 still equals `file_sha256`; the operator can then complete the unlink. Any other state is an integrity error. **Crash before 1:** nothing has changed.

After retirement the first retained segment's `start_previous_hash` equals the retired segment's `last_hash`, preserved in the manifest, so the retained chain still verifies without the deleted bytes.

## Interaction with checkpoints

- `CheckpointAnchor`, `EvidenceCheckpoint`, and `HttpsCheckpointAnchor` are unchanged. `record_count` is the global record number.
- Prefix verification looks up the record at `checkpoint.record_count` in the retained segments. If that number falls inside a retired segment it cannot be re-derived from bytes; it can only be matched against a `segment_retired` boundary (`last_record_number` and `last_hash`). Retirement preconditions ensure the latest checkpoint is verified against the full chain before any bytes are deleted.
- The anchor holds only the **latest** checkpoint. After retirement, assurance about the deleted prefix rests on the preserved export, its recorded hash, and the manifest, not on the anchor alone.

## Security considerations

- An attacker who can rewrite the whole directory (manifest and segments) is detected only through the external anchor, exactly as for the single-file store.
- Deleting a sealed segment without a `segment_retired` entry is detected by manifest/directory reconciliation. Editing a sealed segment is detected by `file_sha256` and the hash chain.
- A forged `segment_retired` entry can hide that evidence once existed; the defence is the preserved verified export and an independently retained manifest copy. Operators should archive the manifest and exports outside the evidence host.
- Sealed segments are read-only, but the evidence host's own privileges are not a trust boundary against a root-level attacker.
- No request bodies, credentials, cookies, authorization headers, or query strings are stored; the event schema is unchanged.

## Migration

An existing single-file log is migrated explicitly with `SegmentedEvidenceStore.migrate_legacy_log(...)`. The API verifies the complete legacy chain, refuses an empty or tampered source, checks any existing checkpoint prefix, and advances the external checkpoint to the full verified source head. It copies the original JSONL bytes unchanged into sealed `segment-00000001.jsonl`, writes the manifest and an empty active `segment-00000002.jsonl`, verifies the staged store, and atomically renames the staging directory into place. The legacy source is never moved, overwritten, or deleted. The destination must not already exist. Migration requires an independent `CheckpointAnchor`; it is not automatic and there is not yet a dedicated CLI command.

## Exit criteria for the implementation

- Rotation produces segments whose first record links to the previous segment's last hash, and global record numbers are continuous.
- Rotation does not seal a segment when checkpoint publication fails; the hard limit makes append fail closed.
- Crash injection at every rotation and retirement step recovers to a valid state or stops with an integrity error; nothing is silently repaired.
- Tampering tests: edited sealed segment, deleted sealed segment, extra segment file, edited or truncated manifest, mismatched `start_previous_hash`, swapped segment order.
- Retirement refuses when the segment is not oldest, not sealed, not exported and re-verified, or not covered by a verified checkpoint, and records `approval_id`.
- Retained range verifies after the oldest segment is retired; checkpoint verification works across a retired boundary.
- Concurrent appenders across a rotation boundary still serialize into one valid chain.
- `verify_sealed_on_append` is tested in both settings, including detection of a tampered sealed segment on append when it is enabled.
- `docs/evidence-storage.md`, `ROADMAP.md`, and `CHANGELOG.md` are updated, and CI passes on Python 3.12–3.14.

## Decisions (2026-11-04)

These resolve the questions raised in the first draft. They apply to the first implementation and should be revisited once target-hardware benchmark results exist.

1. **Append verification scope.** Append always verifies the manifest chain and the active segment. Sealed segments are also verified on every append by default (`verify_sealed_on_append=True`), which preserves the current guarantee. Disabling it is an explicit configuration choice, to be made only after `scripts/benchmark_evidence_store.py` results on representative Linux storage show the cost matters. Retention also bounds how large the retained range can grow.
2. **Anchor history.** Out of scope for the first implementation; the `CheckpointAnchor` contract and `HttpsCheckpointAnchor` stay unchanged. The compensating controls are the retirement preconditions (verified export with a recorded `export_sha256`, checkpoint verified against the full chain before deletion) and the operator duty to archive the manifest and exports off-host. A service-side append-only checkpoint history is recorded as future work for the checkpoint service contract.
3. **Limits.** No size defaults are hard-coded. `max_segment_bytes` (and optionally `max_segment_records`) and `hard_max_segment_bytes` are required explicit configuration, and construction fails unless the hard limit is greater than the soft limit. Operational defaults are chosen only after benchmark measurements; tests use small values.
4. **Event-ID reuse across retired segments.** Accepted limitation for the first implementation: idempotency and conflict detection cover retained segments only. This assumes event IDs are generated uniquely per event; confirm that in `mirage.telemetry.events` before implementing, and revisit (for example with a per-segment ID summary in the manifest) if IDs ever become caller-supplied.


## Initial implementation and usage

The initial implementation exposes `SegmentedEvidenceStore` while preserving
`JsonlEvidenceStore` for existing deployments. The segmented store requires
an injected external `CheckpointAnchor`; it does not silently substitute a
local file or an in-memory anchor.

```python
from mirage.telemetry.segmented import SegmentedEvidenceStore

store = SegmentedEvidenceStore(
    "/var/lib/mirage/evidence",
    max_segment_bytes=8 * 1024 * 1024,
    hard_max_segment_bytes=16 * 1024 * 1024,
    anchor=checkpoint_anchor,
)
receipt = store.append(event)
verification = store.verify_all()

# Rotation is also available explicitly; automatic rotation is attempted
# after an append reaches the soft limit.
store.rotate()

# Retirement requires an independently preserved export and an approval ID.
store.retire_oldest_segment(
    "/secure/archive/segment-00000001.jsonl",
    approval_id="change-ticket-or-operator-approval",
)
```

The byte limits above are illustrative only; operators must choose and
benchmark explicit values for their storage and workload. No production
defaults are provided. Automatic deletion is not performed. The legacy
single-file API and its export/checkpoint behaviour remain available.

The first implementation includes manifest hash verification, continuous
record hashes and global numbering, private segment files, anchored sealing,
external-checkpoint prefix verification, hard-limit refusal, recovery of an
opened-but-missing active segment and of a sealed segment whose successor has
not yet been opened, plus operator-approved oldest-first retirement. Targeted
crash-injection coverage now also exercises manifest fsync before initial segment creation, initialization after segment fsync but before directory fsync, rotation after successor-file fsync but before directory fsync, and migration failures immediately before publication and after rename but before parent-directory fsync. An append interrupted after its record fsync but before receipt delivery is retried idempotently. A partial record write is deliberately not truncated or silently repaired: reopening fails closed with an incomplete-record integrity error. Checkpoint tests cover a valid prefix inside the active segment, a checkpoint ahead of local evidence, and a checkpoint that points inside a retired segment. GitHub Actions run #238 passed 130 tests, the benchmark smoke test, and Ruff on Python 3.12–3.14. During a checkpoint-service outage, appends may continue below the hard limit; rotation is retried after each append. Once the hard limit would be exceeded, append fails closed. Integrity mismatches are never treated as temporary outages. A dedicated migration CLI, exhaustive syscall/filesystem-boundary crash coverage, and target-hardware benchmark results remain outstanding.


## Legacy migration API

The migration is an explicit, non-destructive operation. First configure an independent checkpoint anchor, then:

```python
from mirage.telemetry.segmented import SegmentedEvidenceStore

store = SegmentedEvidenceStore.migrate_legacy_log(
    "/var/lib/mirage/evidence.jsonl",
    "/var/lib/mirage/evidence-segmented",
    max_segment_bytes=8 * 1024 * 1024,
    hard_max_segment_bytes=16 * 1024 * 1024,
    anchor=checkpoint_anchor,
)
print(store.verify_all())
```

The source log remains in place as the rollback copy. Segment 1 is byte-for-byte identical to the legacy file, so its original record hashes and record numbering are preserved; this is not a re-serialization or a new event chain. The external checkpoint is advanced to the full source head before publication. A destination that already exists is rejected. If the process is interrupted before the final directory rename, the source remains intact and an unpublished staging directory may need operator inspection and cleanup. Keep the source until the migrated store has been independently verified and backed up.
