"""Safe connectivity smoke test for osed_vulnsvc using OP_PING."""

from __future__ import annotations

import argparse
from socket import AF_INET, SOCK_STREAM, socket
from struct import pack

OSED_MAGIC = 0x4F534544
OP_PING = 0x1000
OP_ROP = 0x1005
CONTROL_V2_RECORD = 0x0201
RECORD_DATA = 0x0002
MAX_PACKET = 8192
PONG = b"PONG\n"


def build_packet(opcode: int, payload: bytes) -> bytes:
    return pack("<IHHI", OSED_MAGIC, opcode, 0, len(payload)) + payload


def build_event_packet(route_metadata: bytes, event_body: bytes) -> bytes:
    data_offset = 12 + len(route_metadata)
    body = (
        pack("<HHII", RECORD_DATA, 0, data_offset, len(event_body))
        + route_metadata
        + event_body
    )
    if len(body) > MAX_PACKET:
        raise ValueError("event request exceeds the service body limit")
    return pack(
        "<IHHI",
        OSED_MAGIC,
        OP_ROP,
        CONTROL_V2_RECORD,
        len(body),
    ) + body


def run(host: str, port: int, dep3_event: bool = False) -> bytes:
    with socket(AF_INET, SOCK_STREAM) as s:
        s.settimeout(5.0)
        s.connect((host, port))
        if dep3_event:
            s.sendall(build_event_packet(b"ingest/health", b"SMOKE"))
        s.sendall(build_packet(OP_PING, b""))

        response = bytearray()
        while len(response) < len(PONG):
            chunk = s.recv(len(PONG) - len(response))
            if not chunk:
                break
            response.extend(chunk)
        return bytes(response)


def main() -> None:
    parser = argparse.ArgumentParser(description="Safe OP_PING connectivity test")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9999)
    parser.add_argument(
        "--dep3-event",
        action="store_true",
        help="submit a valid DEP v3 event before the connectivity check",
    )
    args = parser.parse_args()

    response = run(args.host, args.port, dep3_event=args.dep3_event)
    if response != PONG:
        raise RuntimeError(f"unexpected server response: {response!r}")
    print("DEP v3 event accepted; PONG" if args.dep3_event else "PONG")


if __name__ == "__main__":
    main()
