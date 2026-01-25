#!/usr/bin/env python3

import argparse
import sys

from pattern.config import PatternConfig
from pattern.offset import OffsetResolver


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Locate the offset of an overwritten value in a cyclic pattern"
    )

    parser.add_argument(
        "-l",
        "--length",
        type=int,
        required=True,
        help="Length of the original pattern",
    )

    parser.add_argument(
        "-q",
        "--query",
        required=True,
        help="Overwritten value (hex string, e.g. 42306142 or 0x42306142)",
    )

    parser.add_argument(
        "--arch",
        choices=["x86", "x64"],
        default="x86",
        help="Architecture (default: x86)",
    )

    parser.add_argument(
        "--word-size",
        type=int,
        choices=[4, 8],
        help="Override word size (4 or 8 bytes)",
    )

    parser.add_argument(
        "--endianness",
        choices=["little", "big"],
        default="little",
        help="Endianness of target (default: little)",
    )

    parser.add_argument(
        "--raw",
        action="store_true",
        help="Treat query as raw memory bytes (no endian reversal)",
    )

    return parser.parse_args()


def main() -> int:
    args = parse_args()

    # Resolve word size
    if args.word_size is not None:
        word_size = args.word_size
    else:
        word_size = 4 if args.arch == "x86" else 8

    try:
        config = PatternConfig(
            word_size=word_size,
            endianness=args.endianness,
        )

        resolver = OffsetResolver(config)

        offset = resolver.find_offset(
            length=args.length,
            query=args.query,
            raw=args.raw,
        )

    except Exception as exc:
        print(f"[-] Error: {exc}", file=sys.stderr)
        return 1

    if offset is None:
        print("[-] No match found")
    else:
        print(f"[*] Exact match at offset {offset}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
