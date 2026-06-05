#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import socket
import sys

BUFFER_SIZE = 4096
DEST_BUFFER = bytearray(BUFFER_SIZE)


def copy_buffer(data):
    copied = min(len(data), BUFFER_SIZE)
    DEST_BUFFER[:copied] = data[:copied]
    if copied < BUFFER_SIZE:
        DEST_BUFFER[copied:] = b"\x00" * (BUFFER_SIZE - copied)
    return copied


def parse_wrapped_payload(data):
    """
    Accept payloads in form: AUTH test:pass\\r\\nSEND <raw-bytes>\\r\\n
    Returns extracted SEND bytes or b"" on parse failure.
    """
    if not data.startswith(b"AUTH "):
        return b""
    split = data.split(b"\r\n", 1)
    if len(split) != 2:
        return b""
    remainder = split[1]
    if not remainder.startswith(b"SEND "):
        return b""
    return remainder[5:].rstrip(b"\r\n")


def handle_client(client, mode, trigger_byte):
    client.sendall(b"220 LABTARGET Ready\r\n")
    data = client.recv(BUFFER_SIZE)
    if not data:
        return

    payload = parse_wrapped_payload(data)
    if not payload:
        client.sendall(b"500 Invalid sequence\r\n")
        return

    if mode == "truncate":
        index = payload.find(bytes([trigger_byte]))
        if index != -1:
            payload = payload[:index]
    elif mode == "crash":
        if bytes([trigger_byte]) in payload:
            print("[!] Crash trigger encountered: 0x{0:02x}".format(trigger_byte), flush=True)
            os._exit(1)

    copied = copy_buffer(payload)
    print("[+] Wrapped payload bytes={0} copied={1}".format(len(payload), copied), flush=True)
    client.sendall(b"250 OK\r\n")


def run_server(host, port, mode, trigger_byte):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(5)
        print(
            "[+] Protocol target on {0}:{1} (mode={2}, trigger=0x{3:02x})".format(
                host, port, mode, trigger_byte
            ),
            flush=True,
        )
        while True:
            client, address = server.accept()
            with client:
                print("[+] Connection from {0}:{1}".format(address[0], address[1]), flush=True)
                handle_client(client, mode, trigger_byte)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=10000)
    parser.add_argument("--mode", choices=["normal", "truncate", "crash"], default="normal")
    parser.add_argument(
        "--trigger-byte",
        type=lambda x: int(x, 0),
        default=0x00,
        help="Byte value used by truncate/crash modes",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    run_server(args.host, args.port, args.mode, args.trigger_byte)
    return 0


if __name__ == "__main__":
    sys.exit(main())
