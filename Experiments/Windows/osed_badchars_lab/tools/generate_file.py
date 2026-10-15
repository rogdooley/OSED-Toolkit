"""Build binary records for the FILE bad-character exercises."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path


HEADER = struct.Struct("<4sBBH")
MAGICS = {"file01": b"BCF1", "file02": b"BCF2", "file03": b"BCF3"}


def build_record(challenge: str, candidate: bytes) -> bytes:
    """Return a length-framed record without changing candidate bytes."""
    if challenge not in MAGICS:
        raise ValueError(f"unsupported file challenge: {challenge}")
    if not candidate or len(candidate) > 4088:
        raise ValueError("candidate must contain 1..4088 bytes")
    return HEADER.pack(MAGICS[challenge], 1, 1, len(candidate)) + candidate


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--challenge", choices=tuple(MAGICS), required=True)
    parser.add_argument("--candidate-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.write_bytes(build_record(args.challenge, args.candidate_file.read_bytes()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
