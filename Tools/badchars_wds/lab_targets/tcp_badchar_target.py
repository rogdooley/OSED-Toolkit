#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import socket
import sys

BUFFER_SIZE = 4096

# Global destination buffer.
# Easy to inspect from a debugger.
DEST_BUFFER = bytearray(BUFFER_SIZE)


def copy_buffer(data: bytes) -> int:
    """
    Simulates a destination copy operation.

    Returns:
        Number of bytes copied.
    """
    copied = min(len(data), BUFFER_SIZE)

    DEST_BUFFER[:copied] = data[:copied]

    if copied < BUFFER_SIZE:
        DEST_BUFFER[copied:] = b"\x00" * (BUFFER_SIZE - copied)

    return copied


def handle_client(
    client: socket.socket,
    mode: str,
    trigger_byte: int,
) -> None:
    data = client.recv(BUFFER_SIZE)

    if not data:
        return

    if mode == "truncate":
        index = data.find(bytes([trigger_byte]))

        if index != -1:
            data = data[:index]

    elif mode == "crash":
        if bytes([trigger_byte]) in data:
            print(
                f"[!] Crash trigger encountered: 0x{trigger_byte:02x}",
                flush=True,
            )
            os._exit(1)

    copied = copy_buffer(data)

    print(
        f"[+] Received={len(data)} Copied={copied}",
        flush=True,
    )

    client.sendall(b"OK")


def run_server(
    host: str,
    port: int,
    mode: str,
    trigger_byte: int,
) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        server.bind((host, port))
        server.listen(5)

        print(
            f"[+] Listening on {host}:{port} "
            f"(mode={mode}, trigger=0x{trigger_byte:02x})",
            flush=True,
        )

        while True:
            client, address = server.accept()

            with client:
                print(
                    f"[+] Connection from {address[0]}:{address[1]}",
                    flush=True,
                )

                handle_client(
                    client=client,
                    mode=mode,
                    trigger_byte=trigger_byte,
                )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--host",
        default="0.0.0.0",
    )

    parser.add_argument(
        "--port",
        type=int,
        default=9999,
    )

    parser.add_argument(
        "--mode",
        choices=[
            "normal",
            "truncate",
            "crash",
        ],
        default="normal",
    )

    parser.add_argument(
        "--trigger-byte",
        type=lambda x: int(x, 0),
        default=0x00,
        help="Byte value used by truncate/crash modes",
    )

    return parser.parse_args()


def main() -> int:
    args = parse_args()

    run_server(
        host=args.host,
        port=args.port,
        mode=args.mode,
        trigger_byte=args.trigger_byte,
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
