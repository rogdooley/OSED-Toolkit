"""
cli.py

Minimal CLI harness demonstrating layout-spec driven payload building.

Existing transport and exploit strategy logic is NOT modified here.
New flags are additive only:

    --layout-spec <file>      Use layout-driven builder instead of manual assembly.
    --shellcode-file <file>   Override shellcode segment source.
    --write-payload <file>    Dump raw payload bytes to file.
    --badchars <hex>          Hex string of forbidden bytes (e.g. 000a0d).

Example:
    python -m exploit.cli --layout-spec layout.json --write-payload out.bin
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from exploit.layout_spec import LayoutSpecParser
from exploit.payload_builder import BadcharError, PayloadBuildError, PayloadBuilder


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Layout-driven payload builder",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--layout-spec",
        metavar="FILE",
        help="YAML or JSON layout spec file",
    )
    p.add_argument(
        "--shellcode-file",
        metavar="FILE",
        help="Override bytes_file segments named 'shellcode'",
    )
    p.add_argument(
        "--write-payload",
        metavar="FILE",
        help="Write raw payload bytes to FILE",
    )
    p.add_argument(
        "--badchars",
        metavar="HEX",
        default="",
        help="Additional forbidden bytes as hex string (e.g. 000a0d)",
    )
    p.add_argument(
        "--strict-overlap",
        action="store_true",
        help="Reject at_offset segments that overwrite earlier segments",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.layout_spec:
        parser.print_help()
        return 0

    # Parse extra badchars
    extra_badchars = b""
    if args.badchars:
        try:
            extra_badchars = bytes.fromhex(args.badchars)
        except ValueError as e:
            print(f"[!] Invalid --badchars hex string: {e}", file=sys.stderr)
            return 1

    # Parse layout spec
    spec_parser = LayoutSpecParser()
    try:
        spec = spec_parser.parse_file(args.layout_spec)
    except FileNotFoundError as e:
        print(f"[!] {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"[!] Failed to parse layout spec: {e}", file=sys.stderr)
        return 1

    # Override shellcode file if requested
    if args.shellcode_file:
        from exploit.layout_spec import BytesFileSegment
        for seg in spec.segments:
            if isinstance(seg, BytesFileSegment) and seg.name == "shellcode":
                seg.path = args.shellcode_file

    # Build
    builder = PayloadBuilder(
        badchars=extra_badchars,
        strict_overlap=args.strict_overlap,
    )

    try:
        payload = builder.build_and_optionally_write(spec, output_file=args.write_payload)
    except BadcharError as e:
        print(f"[!] {e}", file=sys.stderr)
        return 1
    except PayloadBuildError as e:
        print(f"[!] Build error: {e}", file=sys.stderr)
        return 1

    print(f"[+] Payload built: {len(payload)} bytes")
    if args.write_payload:
        print(f"[+] Written to: {args.write_payload}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
