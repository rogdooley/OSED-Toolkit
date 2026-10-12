"""Minimal HTTP server that saves POST request bodies to disk.

Usage:
    python3 Tools/http_exfil_server.py --port 8000
    python3 Tools/http_exfil_server.py --port 8000 --out exfil_data/
"""
from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler


class ExfilHandler(BaseHTTPRequestHandler):

    out_dir: str = "."

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_path = self.path.strip("/").replace("/", "_") or "exfil"
        fname = f"{ts}_{safe_path}.bin"
        out = os.path.join(self.out_dir, fname)

        with open(out, "wb") as f:
            f.write(body)

        print(f"[+] Received {len(body)} bytes -> {out}")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK\n")

    def log_message(self, fmt, *args):
        print(f"[*] {self.client_address[0]} - {fmt % args}")


def main():
    parser = argparse.ArgumentParser(description="HTTP POST exfil catcher")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--out", default=".", help="Directory to save received files")
    args = parser.parse_args()

    os.makedirs(args.out, exist_ok=True)
    ExfilHandler.out_dir = args.out

    server = HTTPServer((args.bind, args.port), ExfilHandler)
    print(f"[*] Listening on {args.bind}:{args.port}, saving to {args.out}/")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down")
        sys.exit(0)


if __name__ == "__main__":
    main()
