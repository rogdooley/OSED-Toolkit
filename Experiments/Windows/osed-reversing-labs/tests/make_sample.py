#!/usr/bin/env python3
"""Create a benign input for the file-format target."""
from __future__ import annotations

import struct
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: make_sample.py OUTPUT")
    entry = struct.pack("<HH20s", 5, 1, b"hello".ljust(20, b"\0"))
    payload = struct.pack("<4sHHI", b"RVF1", 3, 1, len(entry)) + entry
    Path(sys.argv[1]).write_bytes(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
