"""Contracts for independently stored, monotonic evidence checkpoints.

A checkpoint is useful only when its anchor is outside the evidence file's
trust boundary. This module defines the contract; it does not provide a
remote service or pretend that a local sidecar is an independent anchor.
"""

from dataclasses import dataclass
from typing import Protocol


class CheckpointError(RuntimeError):
    """An external evidence checkpoint could not be safely read or updated."""


class CheckpointConflictError(CheckpointError):
    """The external anchor changed since it was read (compare-and-set conflict)."""


@dataclass(frozen=True, slots=True)
class EvidenceCheckpoint:
    """A monotonic commitment to a verified prefix of an evidence log."""

    generation: int
    record_count: int
    head_hash: str

    def __post_init__(self) -> None:
        if self.generation < 1:
            raise ValueError("checkpoint generation must be positive")
        if self.record_count < 1:
            raise ValueError("checkpoint must cover at least one evidence record")
        if (
            len(self.head_hash) != 64
            or any(char not in "0123456789abcdef" for char in self.head_hash)
        ):
            raise ValueError("checkpoint head_hash must be a lowercase SHA-256 digest")


class CheckpointAnchor(Protocol):
    """External store with atomic monotonic compare-and-set semantics.

    Implementations must durably store checkpoints independently of the
    evidence log, reject generation rollback, and atomically compare the
    expected current generation before replacing it.
    """

    def read(self) -> EvidenceCheckpoint | None:
        """Return the current durable checkpoint, or None if uninitialized."""

    def compare_and_set(
        self,
        *,
        expected_generation: int | None,
        checkpoint: EvidenceCheckpoint,
    ) -> None:
        """Atomically publish checkpoint if the current generation matches."""
