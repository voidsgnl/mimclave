"""Command-line entry point for safe, read-only MIRAGE utilities."""

import argparse
import json
from dataclasses import asdict

from mirage.discovery.ports import discover_proc_listeners


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mirage", description="MIRAGE defensive platform utilities")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("discover", help="list local TCP listeners and bound UDP sockets")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "discover":
        listeners = discover_proc_listeners()
        print(json.dumps([asdict(item) for item in listeners], indent=2))
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
