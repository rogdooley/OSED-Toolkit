#!/usr/bin/env python3
"""Emit a bad-character test byte sequence."""

from __future__ import annotations

import argparse


def make_bytes(excluded: set[int]) -> bytes:
    return bytes(x for x in range(0x100) if x not in excluded)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a bad-character sample")
    parser.add_argument("--exclude", action="append", default=[], help="Byte value in hex, e.g. 00 or 0a")
    args = parser.parse_args()

    excluded = {int(value, 16) for value in args.exclude}
    data = make_bytes(excluded)
    print(data.hex())


if __name__ == "__main__":
    main()
