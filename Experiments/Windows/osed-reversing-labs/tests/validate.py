#!/usr/bin/env python3
"""Minimal dependency-free PE32 and import validation for the built lab files."""
from __future__ import annotations

import argparse
import struct
from pathlib import Path


class ValidationError(RuntimeError):
    pass


def u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def validate(path: Path, aslr: bool, winsock: bool) -> None:
    data = path.read_bytes()
    if data[:2] != b"MZ":
        raise ValidationError(f"{path}: missing MZ header")
    pe = u32(data, 0x3C)
    if data[pe : pe + 4] != b"PE\0\0" or u16(data, pe + 4) != 0x14C:
        raise ValidationError(f"{path}: expected PE32 i386")
    optional = pe + 24
    if u16(data, optional) != 0x10B:
        raise ValidationError(f"{path}: expected PE32 optional header")
    flags = u16(data, optional + 70)
    if not flags & 0x100:
        raise ValidationError(f"{path}: NX compatibility missing")
    if bool(flags & 0x40) != aslr:
        raise ValidationError(f"{path}: unexpected ASLR setting")
    lower = data.lower()
    if winsock and b"ws2_32.dll" not in lower:
        raise ValidationError(f"{path}: Winsock import missing")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dist", type=Path, required=True)
    args = parser.parse_args()
    checks = (("target01.exe", False, True), ("target02.exe", True, True), ("target03.exe", False, False))
    for name, aslr, winsock in checks:
        validate(args.dist / name, aslr, winsock)
    print("PE32 architecture, imports, and mitigation flags verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
