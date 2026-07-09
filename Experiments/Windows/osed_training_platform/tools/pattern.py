#!/usr/bin/env python3
"""Generate a cyclic pattern for offset work."""

from __future__ import annotations

import argparse


def cyclic_pattern(length: int) -> bytes:
    a = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    b = b"abcdefghijklmnopqrstuvwxyz"
    c = b"0123456789"
    out = bytearray()

    for x in a:
        for y in b:
            for z in c:
                if len(out) >= length:
                    return bytes(out[:length])
                out.extend([x, y, z])
    return bytes(out[:length])


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a cyclic pattern")
    parser.add_argument("length", type=int)
    args = parser.parse_args()
    print(cyclic_pattern(args.length).decode("ascii"))


if __name__ == "__main__":
    main()
