#!/usr/bin/env python3

"""
Create a cyclic-pattern payload file for the Win32/x86 lessons.

Run from the repo root (or ensure Tools/ is importable):
  python lessons/win32_x86/tools/make_pattern_payload.py --length 600 --out payload.bin
"""

import argparse
from pathlib import Path

from Tools.pattern.config import PatternConfig
from Tools.pattern.generator import PatternGenerator


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Write a cyclic pattern to a file")
    p.add_argument("--length", type=int, required=True, help="Pattern length in bytes")
    p.add_argument("--out", required=True, help="Output file path")
    p.add_argument("--arch", choices=["x86", "x64"], default="x86")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    word_size = 4 if args.arch == "x86" else 8
    cfg = PatternConfig(word_size=word_size, endianness="little")
    pat = PatternGenerator(cfg).create(args.length)
    out = Path(args.out)
    out.write_bytes(pat)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

