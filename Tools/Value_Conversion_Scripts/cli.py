from __future__ import annotations

"""Console entry point for the value conversion tools."""

import argparse
import sys
from pathlib import Path

ROOT_DIR = str(Path(__file__).resolve().parents[2])
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from Tools.Value_Conversion_Scripts.string2hex import (
    build_ip_parser,
    build_sockaddr_parser,
    build_string_parser,
    main as string2hex_main,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="value-convert",
        description="Shellcode-oriented conversion helpers for strings, IPv4 addresses, and sockaddr_in values.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", title="subcommands", metavar="{string,ip,sockaddr}")
    build_string_parser(subparsers)
    build_ip_parser(subparsers)
    build_sockaddr_parser(subparsers)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else list(argv)
    parser = build_parser()
    if not args:
        parser.print_help()
        return 0
    if args[0] in {"-h", "--help"}:
        parser.print_help()
        return 0

    return string2hex_main(args)


if __name__ == "__main__":
    raise SystemExit(main())
