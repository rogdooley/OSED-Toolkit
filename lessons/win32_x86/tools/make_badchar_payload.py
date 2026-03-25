#!/usr/bin/env python3

"""
Write a canonical badchar test sequence to a file.

This complements Tools.badchars (analysis), by making it easy to generate the
byte stream you will send/inspect in your debugger.

Example:
  python lessons/win32_x86/tools/make_badchar_payload.py --exclude 00 --out badchars.bin
"""

import argparse
from pathlib import Path

from Tools.badchars.badchars import BadCharAnalyzer


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Write badchar test bytes to a file")
    p.add_argument("--exclude", default="00", help="Comma-separated excluded bytes (hex)")
    p.add_argument("--out", required=True, help="Output file path")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    exclude = []
    if args.exclude:
        for part in args.exclude.split(","):
            t = part.strip().lower()
            if not t:
                continue
            if t.startswith("0x"):
                t = t[2:]
            exclude.append(int(t, 16))

    analyzer = BadCharAnalyzer(exclude=exclude)
    data = analyzer.generate_test_bytes()
    Path(args.out).write_bytes(data)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

