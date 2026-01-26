#!/usr/bin/env python3

import argparse
import sys

from Tools.badchars.badchars import BadCharAnalyzer


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze bad characters by comparing expected vs observed bytes"
    )

    parser.add_argument(
        "--expected",
        required=True,
        help="Expected bytes (hex string, e.g. 01020304)",
    )

    parser.add_argument(
        "--observed",
        required=True,
        help="Observed bytes from memory (hex string)",
    )

    parser.add_argument(
        "--exclude",
        default="00",
        help="Comma-separated hex bytes to exclude (default: 00)",
    )

    return parser.parse_args()


def parse_hex_bytes(value: str) -> bytes:
    value = value.replace("0x", "").replace(",", "").replace(" ", "")
    return bytes.fromhex(value)


def main() -> int:
    args = parse_args()

    try:
        expected = parse_hex_bytes(args.expected)
        observed = parse_hex_bytes(args.observed)

        exclude = [int(b, 16) for b in args.exclude.split(",")] if args.exclude else []

        analyzer = BadCharAnalyzer(exclude=exclude)
        result = analyzer.analyze(expected, observed)

    except Exception as exc:
        print(f"[-] Error: {exc}", file=sys.stderr)
        return 1

    if not result:
        print("[+] No bad characters detected")
        return 0

    if result.badchars:
        print("[!] Bad characters:")
        print(" ".join(f"{b:02x}" for b in result.badchars))

    if result.transformed:
        print("[!] Transformed bytes:")
        for src, dst in result.transformed.items():
            print(f"{src:02x} -> {dst:02x}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
