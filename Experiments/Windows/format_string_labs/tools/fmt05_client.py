"""Transport scaffold for the local fmt05_service practice target."""

from __future__ import annotations

import argparse
from socket import AF_INET, SOCK_STREAM, socket
from struct import pack, unpack

MAGIC = 0x324D5446
OP_FORMAT = 1
OP_EXECUTE = 2
PORT = 31337
ARGUMENT_COUNT = 8
FORMAT_SIZE = 256


def receive_exact(connection: socket, length: int) -> bytes:
    data = bytearray()
    while len(data) < length:
        chunk = connection.recv(length - len(data))
        if not chunk:
            raise RuntimeError("connection closed before the response completed")
        data.extend(chunk)
    return bytes(data)


def build_request(opcode: int, format_string: bytes, arguments: list[int]) -> bytes:
    if len(format_string) >= FORMAT_SIZE:
        raise ValueError("format string must be shorter than 256 bytes")
    if len(arguments) > ARGUMENT_COUNT:
        raise ValueError("at most eight explicit arguments are available")
    padded_arguments = arguments + [0] * (ARGUMENT_COUNT - len(arguments))
    padded_format = format_string.ljust(FORMAT_SIZE, b"\x00")
    return pack("<II8I256s", MAGIC, opcode, *padded_arguments, padded_format)


def exchange(host: str, request: bytes, expect_response: bool) -> bytes:
    with socket(AF_INET, SOCK_STREAM) as connection:
        connection.connect((host, PORT))
        connection.sendall(request)
        if not expect_response:
            return b""
        length = unpack("<I", receive_exact(connection, 4))[0]
        return receive_exact(connection, length)


def auto_int(value: str) -> int:
    return int(value, 0)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    subparsers = parser.add_subparsers(dest="command", required=True)

    format_parser = subparsers.add_parser("format", help="submit a format request")
    format_parser.add_argument("--text", required=True)
    format_parser.add_argument("--arg", type=auto_int, action="append", default=[])
    subparsers.add_parser("execute", help="invoke the persistent action pointer")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.command == "execute":
        exchange(args.host, build_request(OP_EXECUTE, b"", []), False)
        return

    request = build_request(OP_FORMAT, args.text.encode("ascii"), args.arg)
    response = exchange(args.host, request, True)
    print(response.decode("ascii", errors="backslashreplace"))


if __name__ == "__main__":
    main()
