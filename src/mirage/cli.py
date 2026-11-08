"""Command-line entry point for safe, read-only MIRAGE utilities."""

import argparse
import json
import os
import sys
from dataclasses import asdict
from pathlib import Path

from mirage.config.loader import ConfigLoadError, load_config
from mirage.config.registry import ProfileRegistry
from mirage.discovery.ports import discover_proc_listeners
from mirage.telemetry.checkpoints import CheckpointError
from mirage.telemetry.https_anchor import HttpsCheckpointAnchor
from mirage.telemetry.segmented import SegmentedEvidenceStore
from mirage.telemetry.store import EvidenceStoreError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mirage",
        description="MIRAGE defensive platform utilities",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("discover", help="list local TCP listeners and bound UDP sockets")
    validate = subparsers.add_parser("validate-config", help="validate a TOML configuration")
    validate.add_argument("path", type=Path, help="path to MIRAGE TOML configuration")
    migrate = subparsers.add_parser(
        "migrate-evidence", help="migrate a legacy JSONL evidence log to segmented storage"
    )
    migrate.add_argument("source", type=Path, help="legacy JSONL evidence file")
    migrate.add_argument("destination", type=Path, help="new segmented evidence directory")
    migrate.add_argument("--checkpoint-url", required=True, help="HTTPS checkpoint resource URL")
    migrate.add_argument(
        "--token-env", default="MIRAGE_CHECKPOINT_TOKEN",
        help="environment variable containing the checkpoint bearer token",
    )
    migrate.add_argument("--max-segment-bytes", type=int, required=True)
    migrate.add_argument("--hard-max-segment-bytes", type=int, required=True)
    migrate.add_argument("--timeout", type=float, default=5.0)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "discover":
        listeners = discover_proc_listeners()
        print(json.dumps([asdict(item) for item in listeners], indent=2))
        return 0

    if args.command == "validate-config":
        try:
            config = load_config(args.path)
            report = ProfileRegistry(config).validate()
        except (ConfigLoadError, ValueError) as exc:
            print(f"Configuration invalid: {exc}", file=sys.stderr)
            return 2

        if report.issues:
            for issue in report.issues:
                print(f"ERROR [{issue.code}]: {issue.message}", file=sys.stderr)
            return 1

        print(
            "Configuration valid: "
            f"{len(config.profiles)} profile(s), "
            f"{len(config.mappings)} listener mapping(s), "
            f"{len(config.protected_services)} protected service record(s)."
        )
        return 0

    if args.command == "migrate-evidence":
        token = os.environ.get(args.token_env)
        if not token:
            print(
                f"Evidence migration failed: environment variable {args.token_env!r} is not set.",
                file=sys.stderr,
            )
            return 2
        try:
            anchor = HttpsCheckpointAnchor(
                args.checkpoint_url, token, timeout=args.timeout
            )
            store = SegmentedEvidenceStore.migrate_legacy_log(
                args.source,
                args.destination,
                max_segment_bytes=args.max_segment_bytes,
                hard_max_segment_bytes=args.hard_max_segment_bytes,
                anchor=anchor,
            )
            verification = store.verify_all()
        except (CheckpointError, EvidenceStoreError, OSError, ValueError) as exc:
            print(f"Evidence migration failed: {exc}", file=sys.stderr)
            return 2

        print(
            "Evidence migration complete: "
            f"{verification.record_count} record(s); "
            f"head hash {verification.head_hash}. "
            "The legacy source was left unchanged."
        )
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
