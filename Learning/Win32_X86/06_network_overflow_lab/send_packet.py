#!/usr/bin/env python3

from __future__ import annotations

import argparse
import socket
import struct
from dataclasses import dataclass


MAGIC = 0x4445534F  # "OSED" little-endian
VERSION = 1
OPCODE_PING = 0x1001
OPCODE_ECHO = 0x1002
OPCODE_COPY_PAYLOAD = 0x1337

RECORD_METADATA = 1
RECORD_COMMAND = 2
RECORD_PAYLOAD = 3


@dataclass
class Record:
    type: int
    flags: int
    body: bytes

    def pack(self) -> bytes:
        return struct.pack("<HHI", self.type, self.flags, len(self.body)) + self.body


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Send a packet to mini_proto_vuln")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=11460)
    parser.add_argument("--opcode", required=True, help="Opcode as decimal or 0x-prefixed hex")
    parser.add_argument("--size", type=int, default=0, help="Payload size before padding")
    parser.add_argument("--copy-len", type=int, default=None, help="Record copy length field")
    parser.add_argument("--pattern", default="A", help="Pattern used to fill record bodies")
    return parser.parse_args()


def build_pattern(pattern: str, size: int) -> bytes:
    if size <= 0:
        return b""

    data = pattern.encode("ascii", errors="ignore") or b"A"
    out = bytearray()
    while len(out) < size:
        out.extend(data)
    return bytes(out[:size])


def build_packet(opcode: int, size: int, copy_len: int, pattern: str) -> bytes:
    client_name = build_pattern("lab-client", 10)
    note = build_pattern("note", 4)

    records = [
        Record(RECORD_METADATA, 0, client_name),
        Record(RECORD_COMMAND, 0, note),
    ]

    if opcode in (OPCODE_ECHO, OPCODE_COPY_PAYLOAD):
        body_len = max(size, copy_len)
        payload = build_pattern(pattern, body_len)
        payload_body = struct.pack("<I", copy_len) + payload
        records.append(Record(RECORD_PAYLOAD, 0, payload_body))

    packed_records = b"".join(record.pack() for record in records)
    header = struct.pack(
        "<IHHII",
        MAGIC,
        VERSION,
        opcode,
        16 + len(packed_records),
        len(records),
    )
    return header + packed_records


def main() -> int:
    args = parse_args()
    opcode = int(args.opcode, 0)
    copy_len = args.copy_len if args.copy_len is not None else args.size

    packet = build_packet(opcode, args.size, copy_len, args.pattern)
    with socket.create_connection((args.host, args.port), timeout=2.0) as sock:
        sock.sendall(packet)
        try:
            response = sock.recv(1024)
        except socket.timeout:
            response = b""

    if response:
        print(response.decode("ascii", errors="replace").rstrip())
    else:
        print("(no response)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
