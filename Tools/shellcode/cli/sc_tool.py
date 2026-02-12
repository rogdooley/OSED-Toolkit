#!/usr/bin/env python3

import argparse
import sys

from Tools.shellcode.analyze import analyze_shellcode
from Tools.shellcode.formatting import format_bytes
from Tools.shellcode.parsing import (
    ParseError,
    parse_c_array,
    parse_escaped_hex,
    parse_hex,
    parse_py_bytes_literal,
)


def _parse_badchars(s: str) -> list[int]:
    if not s:
        return []
    items = []
    for part in s.split(","):
        p = part.strip().lower()
        if not p:
            continue
        if p.startswith("0x"):
            p = p[2:]
        if len(p) != 2:
            raise ValueError(f"badchar must be 1 byte (got {part!r})")
        items.append(int(p, 16))
    return items


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Shellcode helper: parse, analyze, and format bytes for exploit dev workflows"
    )
    p.add_argument(
        "--input",
        help="Read from file instead of stdin (text formats only).",
    )
    p.add_argument(
        "--bin",
        help="Read raw bytes from a binary file instead of parsing text.",
    )
    p.add_argument(
        "--in-format",
        choices=["hex", "escaped", "c", "py"],
        default="hex",
        help="Input format for text parsing (default: hex).",
    )
    p.add_argument(
        "--out-format",
        choices=["hex", "escaped", "c", "py"],
        default="py",
        help="Output format (default: py).",
    )
    p.add_argument(
        "--width",
        type=int,
        default=16,
        help="Bytes per line for py/c formatting (default: 16).",
    )
    p.add_argument(
        "--var",
        default="sc",
        help="Variable name for py/c formatting (default: sc).",
    )
    p.add_argument(
        "--badchars",
        default="00,0a,0d",
        help="Comma-separated bad chars to check (default: 00,0a,0d).",
    )
    p.add_argument(
        "--no-format",
        action="store_true",
        help="Do not print reformatted bytes (only analysis).",
    )
    return p.parse_args()


def _read_text(path: str | None) -> str:
    if path:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    return sys.stdin.read()


def _read_bin(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def _parse_input(text: str, fmt: str) -> bytes:
    fmt = fmt.lower()
    if fmt == "hex":
        return parse_hex(text)
    if fmt == "escaped":
        return parse_escaped_hex(text)
    if fmt == "c":
        return parse_c_array(text)
    if fmt == "py":
        return parse_py_bytes_literal(text)
    raise ValueError(f"unknown input format: {fmt}")


def main() -> int:
    args = parse_args()

    try:
        if args.bin and args.input:
            raise ValueError("use only one of --bin or --input")

        if args.bin:
            data = _read_bin(args.bin)
        else:
            text = _read_text(args.input)
            if not text.strip():
                raise ParseError("no input provided")
            data = _parse_input(text, args.in_format)

        badchars = _parse_badchars(args.badchars)
        report = analyze_shellcode(data, badchars=badchars)

    except (ParseError, ValueError) as exc:
        print(f"[-] Error: {exc}", file=sys.stderr)
        return 1

    print("[*] Shellcode report")
    print(f"  length: {report.length}")
    print(f"  md5: {report.md5}")
    print(f"  sha256: {report.sha256}")
    if report.badchars:
        print("  badchars present: " + " ".join(f"{b:02x}" for b in report.badchars))
    else:
        print("  badchars present: none")

    if not args.no_format:
        print("")
        print("[*] Formatted output")
        print(
            format_bytes(
                data,
                fmt=args.out_format,
                width=args.width,
                var_name=args.var,
            )
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
