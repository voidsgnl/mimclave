"""Command-line entry point for safe, read-only MIRAGE utilities."""

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from mirage.config.loader import ConfigLoadError, load_config
from mirage.config.registry import ProfileRegistry
from mirage.discovery.ports import discover_proc_listeners


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mirage",
        description="MIRAGE defensive platform utilities",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("discover", help="list local TCP listeners and bound UDP sockets")
    validate = subparsers.add_parser("validate-config", help="validate a TOML configuration")
    validate.add_argument("path", type=Path, help="path to MIRAGE TOML configuration")
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

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
