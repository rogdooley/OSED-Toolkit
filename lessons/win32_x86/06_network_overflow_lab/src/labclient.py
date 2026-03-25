#!/usr/bin/env python3

"""
Client for lessons/win32_x86/06_network_overflow_lab.

Run on Windows:
  py -3 labclient.py --host 127.0.0.1 --port 9001 --cmd PING
  py -3 labclient.py --host 127.0.0.1 --port 9001 --cmd OVER --len 600
  py -3 labclient.py --host 127.0.0.1 --port 9001 --cmd OVER --pattern-file pattern.txt
"""

import argparse
import socket
from pathlib import Path


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Lab client for the overflow server")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=9001)
    p.add_argument("--cmd", choices=["PING", "OVER"], required=True)
    p.add_argument("--len", type=int, help="For OVER: send 'A' repeated len times")
    p.add_argument("--pattern-file", help="For OVER: read payload text from file")
    return p.parse_args()


def main() -> int:
    args = parse_args()

    if args.cmd == "OVER":
        if (args.len is None) == (args.pattern_file is None):
            raise SystemExit("For OVER, specify exactly one of --len or --pattern-file")

        if args.len is not None:
            payload = "A" * args.len
        else:
            payload = Path(args.pattern_file).read_text(encoding="utf-8", errors="ignore")
            payload = payload.strip("\r\n")

        line = f"OVER {payload}\r\n"
    else:
        line = "PING\r\n"

    data = line.encode("ascii", errors="ignore")
    with socket.create_connection((args.host, args.port), timeout=2.0) as s:
        s.sendall(data)
        try:
            resp = s.recv(1024)
        except socket.timeout:
            resp = b""

    if resp:
        print(resp.decode("ascii", errors="replace").strip())
    else:
        print("(no response)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

