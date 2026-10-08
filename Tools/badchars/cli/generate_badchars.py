#!/usr/bin/env python3
"""Generate a canonical byte sequence for bad-character testing."""

from __future__ import annotations

import argparse
from collections.abc import Sequence

from Tools.badchars.badchars import BadCharAnalyzer


def parse_exclusions(value: str) -> tuple[int, ...]:
    """Parse comma/space-separated hexadecimal bytes."""
    if not value.strip():
        return ()

    tokens = value.replace(",", " ").split()
    exclusions: list[int] = []
    for token in tokens:
        normalized = token.removeprefix("0x").removeprefix("\\x")
        if len(normalized) != 2:
            raise argparse.ArgumentTypeError(
                f"invalid byte {token!r}; use two hex digits (for example: 0a)"
            )
        try:
            byte = int(normalized, 16)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(f"invalid hexadecimal byte {token!r}") from exc
        if byte not in exclusions:
            exclusions.append(byte)
    return tuple(exclusions)


def escaped(data: bytes) -> str:
    return "".join(f"\\x{byte:02x}" for byte in data)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="badchars",
        description="Generate bytes for bad-character testing.",
    )
    parser.add_argument(
        "-e",
        "--exclude",
        type=parse_exclusions,
        default=(0x00,),
        metavar="BYTES",
        help="hex bytes to omit, comma or space separated (default: 00)",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=("python", "escaped", "hex"),
        default="python",
        help="output format (default: python)",
    )
    parser.add_argument(
        "-n",
        "--name",
        default="badchars",
        help="variable name used by Python output (default: badchars)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    data = BadCharAnalyzer(exclude=args.exclude).generate_test_bytes()

    if args.format == "python":
        print(f'{args.name} = b"{escaped(data)}"')
    elif args.format == "escaped":
        print(escaped(data))
    else:
        print(data.hex())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
