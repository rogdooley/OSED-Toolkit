"""Safe protocol smoke test for osed_vulnsvc.

Exercises only OP_LEAK for connectivity and parser verification.
"""

from __future__ import annotations

import argparse
from socket import AF_INET, SOCK_STREAM, socket
from struct import pack

OSED_MAGIC = 0x4F534544
OP_LEAK = 0x1004


def build_packet(opcode: int, payload: bytes) -> bytes:
    return pack("<IHHI", OSED_MAGIC, opcode, 0, len(payload)) + payload


def run(host: str, port: int) -> bytes:
    packet = build_packet(OP_LEAK, b"PING")
    with socket(AF_INET, SOCK_STREAM) as s:
        s.connect((host, port))
        s.sendall(packet)
        return s.recv(1024)


def main() -> None:
    parser = argparse.ArgumentParser(description="Safe OP_LEAK smoke test")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9999)
    args = parser.parse_args()

    response = run(args.host, args.port)
    print(response.decode("ascii", errors="replace").strip())


if __name__ == "__main__":
    main()
