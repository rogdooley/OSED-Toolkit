#!/usr/bin/env python3

"""
Length fuzzer for Win32/x86 lesson binaries.

This does NOT exploit anything. It only:
- executes a local process with varying input lengths
- notes non-zero exit codes / timeouts
- saves the last payload

Run on Windows:
  py -3 fuzz_len.py --exe vuln_strcpy_x86.exe --max 2000 --step 50
"""

import argparse
import os
import subprocess
import time
from pathlib import Path


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Minimal length fuzzer")
    p.add_argument("--exe", required=True, help="Path to target exe")
    p.add_argument("--max", type=int, default=2000, help="Max length to try")
    p.add_argument("--step", type=int, default=50, help="Step size")
    p.add_argument("--timeout", type=float, default=2.0, help="Seconds per run")
    p.add_argument("--prefix", default="A", help="Byte/char to repeat (default: A)")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    exe = Path(args.exe)
    if not exe.exists():
        raise SystemExit(f"[-] exe not found: {exe}")

    artifacts = Path(__file__).resolve().parent.parent / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)

    last_ok = None
    last_payload = None

    for n in range(args.step, args.max + 1, args.step):
        payload = (args.prefix * n).encode("ascii", errors="ignore")
        cmd = [str(exe), payload.decode("ascii", errors="ignore")]

        t0 = time.time()
        try:
            p = subprocess.run(
                cmd,
                capture_output=True,
                timeout=args.timeout,
                check=False,
            )
            dt = time.time() - t0

            if p.returncode != 0:
                print(f"[!] returncode={p.returncode} at len={n} (dt={dt:.2f}s)")
                last_payload = payload
                break

            print(f"[*] ok len={n} (dt={dt:.2f}s)")
            last_ok = n

        except subprocess.TimeoutExpired:
            print(f"[!] timeout at len={n}")
            last_payload = payload
            break

    stamp = time.strftime("%Y%m%d_%H%M%S")
    summary_path = artifacts / f"run_{stamp}.txt"
    with summary_path.open("w", encoding="utf-8") as f:
        f.write(f"exe={exe}\n")
        f.write(f"last_ok={last_ok}\n")
        if last_payload is not None:
            f.write(f"last_payload_len={len(last_payload)}\n")

    if last_payload is not None:
        payload_path = artifacts / f"payload_{stamp}.txt"
        with payload_path.open("wb") as f:
            f.write(last_payload)
        print(f"[*] saved payload: {payload_path}")

    print(f"[*] saved summary: {summary_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

