"""Command-line entry point for safe MIRAGE utilities and operator workflows."""

import argparse
import asyncio
import json
import os
import sys
from dataclasses import asdict
from ipaddress import ip_address
from pathlib import Path

from mirage.config.loader import ConfigLoadError, load_config
from mirage.config.models import Protocol
from mirage.config.registry import ProfileRegistry
from mirage.discovery.ports import discover_proc_listeners
from mirage.emulation.http import HttpDecoy
from mirage.telemetry.checkpoints import CheckpointError
from mirage.telemetry.https_anchor import HttpsCheckpointAnchor
from mirage.telemetry.segmented import SegmentedEvidenceStore
from mirage.telemetry.store import EvidenceStoreError, JsonlEvidenceStore
from mirage.transport.http_server import HttpDecoyServer


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mirage",
        description="MIRAGE defensive platform utilities",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("discover", help="list local TCP listeners and bound UDP sockets")
    validate = subparsers.add_parser("validate-config", help="validate a TOML configuration")
    validate.add_argument("path", type=Path, help="path to MIRAGE TOML configuration")
    serve = subparsers.add_parser(
        "serve-http", help="run a loopback-only HTTP decoy and record interactions"
    )
    serve.add_argument("path", type=Path, help="path to MIRAGE TOML configuration")
    serve.add_argument("--profile-id", required=True, help="configured HTTP decoy profile ID")
    serve.add_argument(
        "--host", default="127.0.0.1",
        help="literal loopback address only (default: 127.0.0.1)",
    )
    serve.add_argument("--port", type=int, default=8080, help="TCP port (default: 8080; 0 selects a free port)")
    serve.add_argument(
        "--evidence", type=Path, default=Path("mirage-evidence.jsonl"),
        help="append-only evidence file (default: ./mirage-evidence.jsonl)",
    )
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


def _create_http_server(
    config_path: Path,
    *,
    profile_id: str,
    host: str,
    port: int,
    evidence_path: Path,
) -> HttpDecoyServer:
    """Build a validated local HTTP decoy whose responses require durable evidence."""
    try:
        address = ip_address(host)
    except ValueError as exc:
        raise ValueError("host must be a literal loopback IP address") from exc
    if not address.is_loopback:
        raise ValueError("MIRAGE prototype listeners are restricted to loopback addresses")

    config = load_config(config_path)
    registry = ProfileRegistry(config)
    report = registry.validate()
    if report.issues:
        details = "; ".join(f"{issue.code}: {issue.message}" for issue in report.issues)
        raise ValueError(f"configuration policy validation failed: {details}")

    profile = registry.profiles.get(profile_id)
    if profile is None:
        raise ValueError(f"unknown decoy profile: {profile_id}")
    if profile.protocol is not Protocol.HTTP:
        raise ValueError("serve-http currently supports HTTP profiles only")
    if not any(mapping.profile_id == profile_id for mapping in config.mappings):
        raise ValueError(f"profile {profile_id!r} is not referenced by a listener mapping")

    evidence_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    store = JsonlEvidenceStore(evidence_path)
    if evidence_path.exists():
        # Refuse to start against an existing malformed or tampered evidence file.
        store.verify()

    return HttpDecoyServer(
        HttpDecoy(profile),
        event_sink=store.append,
        host=str(address),
        port=port,
    )


async def _serve_http(args: argparse.Namespace) -> None:
    server = _create_http_server(
        args.path,
        profile_id=args.profile_id,
        host=args.host,
        port=args.port,
        evidence_path=args.evidence,
    )
    await server.start()
    host, port = server.address
    print(
        f"MIRAGE HTTP decoy listening on http://{host}:{port} "
        f"(profile={args.profile_id}; evidence={args.evidence})",
        flush=True,
    )
    try:
        await asyncio.Event().wait()
    finally:
        await server.close()


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

    if args.command == "serve-http":
        try:
            asyncio.run(_serve_http(args))
        except KeyboardInterrupt:
            print("\\nMIRAGE HTTP decoy stopped.", flush=True)
            return 130
        except (ConfigLoadError, EvidenceStoreError, OSError, ValueError, RuntimeError) as exc:
            print(f"HTTP decoy failed: {exc}", file=sys.stderr)
            return 2
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
