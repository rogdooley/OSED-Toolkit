#!/usr/bin/env python3

import argparse
import sys

from Tools.pattern.config import PatternConfig
from Tools.pattern.generator import PatternGenerator


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a deterministic cyclic pattern"
    )

    parser.add_argument(
        "-l",
        "--length",
        type=int,
        required=True,
        help="Length of the pattern to generate",
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
        help="Endianness (kept for symmetry; does not affect generation)",
    )

    parser.add_argument(
        "--hex",
        action="store_true",
        help="Output pattern as hex instead of ASCII",
    )

    parser.add_argument(
        "--newline",
        action="store_true",
        help="Append a newline to the output",
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

        generator = PatternGenerator(config)
        pattern = generator.create(args.length)

    except Exception as exc:
        print(f"[-] Error: {exc}", file=sys.stderr)
        return 1

    if args.hex:
        output = pattern.hex()
    else:
        try:
            output = pattern.decode("ascii")
        except UnicodeDecodeError:
            print("[-] Error: pattern contains non-ASCII bytes", file=sys.stderr)
            return 1

    if args.newline:
        output += "\n"

    sys.stdout.write(output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
