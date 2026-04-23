#!/usr/bin/env python3
"""CLI wrapper for unified egghunter generator."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from Tools.egghunter.unified_builder import EgghunterBuilder, EgghunterConfig


def _parse_hex_bytes(value: str, *, field_name: str) -> bytes:
    s = value.strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    s = s.replace("\\x", "").replace(" ", "")
    if s == "":
        return b""
    if len(s) % 2 != 0:
        raise argparse.ArgumentTypeError(f"{field_name} must contain an even number of hex characters")
    try:
        return bytes.fromhex(s)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"Invalid {field_name} hex string: {value}") from exc


def _parse_tag(tag: str) -> bytes:
    b = tag.encode("latin-1")
    if len(b) != 4:
        raise argparse.ArgumentTypeError("tag must be exactly 4 bytes/chars")
    return b


def _to_escaped(buf: bytes) -> str:
    return "".join(f"\\x{x:02x}" for x in buf)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Unified egghunter generator (SEH + syscall)")
    p.add_argument("--strategy", choices=["seh_win10", "seh_classic", "syscall", "auto"], default="seh_win10")
    p.add_argument("--tag", default="W00T", help="4-byte tag (default: W00T)")
    p.add_argument("--badchars", default="", help=r"Hex bytes to avoid, e.g. '\\x00\\x0a\\x0d' or '000a0d'")
    p.add_argument("--nop-sled-size", type=int, default=0)
    p.add_argument("--stackbase-adjust", type=int, default=4)
    p.add_argument("--target", default="win10_x86")
    p.add_argument("--syscall-id", type=lambda v: int(v, 0), default=None, help="Override syscall id (e.g. 0x1C6)")
    p.add_argument("--debug", action="store_true")
    p.add_argument("--output-asm", action="store_true")
    p.add_argument("--format", choices=["escaped", "python", "hex", "raw"], default="python")
    p.add_argument("--out", help="Optional output file path")
    p.add_argument("--print-egg", action="store_true", help="Also print duplicated egg tag (tag*2)")
    return p


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    try:
        tag = _parse_tag(args.tag)
        badchars = _parse_hex_bytes(args.badchars, field_name="badchars")

        cfg = EgghunterConfig(
            tag=tag,
            badchars=badchars,
            nop_sled_size=args.nop_sled_size,
            stackbase_adjust=args.stackbase_adjust,
            debug=args.debug,
            output_asm=args.output_asm,
            target=args.target,
            syscall_id_override=args.syscall_id,
        )

        payload = EgghunterBuilder(cfg).build(strategy=args.strategy)
        egg = tag * 2

        if args.out:
            Path(args.out).write_bytes(payload)

        if args.format == "raw":
            sys.stdout.buffer.write(payload)
            if args.print_egg:
                sys.stdout.write("\n")
                sys.stdout.write(f"egg = b\"{_to_escaped(egg)}\"\n")
            return 0

        if args.format == "escaped":
            print(_to_escaped(payload))
        elif args.format == "hex":
            print(payload.hex())
        else:
            print(f'hunter = b"{_to_escaped(payload)}"')

        if args.print_egg:
            print(f'egg = b"{_to_escaped(egg)}"')

        if args.out:
            print(f"[+] wrote {len(payload)} bytes to {args.out}")

        return 0
    except Exception as exc:
        print(f"[-] Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
