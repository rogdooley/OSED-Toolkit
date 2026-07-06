"""Badchar-safe immediate value encoding for x86 payload templates.

When a 32-bit or 16-bit constant contains bytes in the manifest badchar set,
those bytes cannot appear in the assembled shellcode. This module provides
helpers that substitute a (value XOR mask) / XOR-back pair where both the
encoded value and the mask are free of badchars.

Typical usage in a template:

    from ..encode import encode_dword, encode_word, safe_push_word_as_dword

    return "\\n".join([
        ...
        *safe_push_word_as_dword(0x0202, config.badchars),   # WSAStartup ver
        ...
        "    xor  eax, eax",
        *encode_word(port_be, config.badchars, "ax"),
        "    mov  word ptr [edi+0x02], ax",
        *encode_dword(ip_be, config.badchars, "eax"),
        "    mov  dword ptr [edi+0x04], eax",
        ...
    ])
"""
from __future__ import annotations


def _find_mask_byte(v_byte: int, badchars: set[int]) -> int:
    """Return a mask byte m such that m and (v_byte XOR m) are both not in badchars."""
    for m in range(1, 256):
        if m not in badchars and (v_byte ^ m) not in badchars:
            return m
    raise ValueError(
        f"Cannot encode byte 0x{v_byte:02x}: no valid mask exists for "
        f"badchar set {sorted(f'0x{b:02x}' for b in badchars)}"
    )


def encode_dword(value: int, badchars: set[int], reg: str = "eax") -> list[str]:
    """Return assembly lines that load a 32-bit value into reg, free of badchars.

    If the value is already clean, emits a single mov.
    Otherwise emits mov + xor using a computed per-byte mask.
    """
    v_bytes = [(value >> (8 * i)) & 0xFF for i in range(4)]
    if not any(b in badchars for b in v_bytes):
        return [f"    mov  {reg}, 0x{value:08x}"]
    mask_bytes = [_find_mask_byte(b, badchars) for b in v_bytes]
    mask    = sum(m << (8 * i) for i, m in enumerate(mask_bytes))
    encoded = value ^ mask
    return [
        f"    mov  {reg}, 0x{encoded:08x}",
        f"    xor  {reg}, 0x{mask:08x}",
    ]


def encode_word(value: int, badchars: set[int], reg: str = "ax") -> list[str]:
    """Return assembly lines that load a 16-bit value into reg, free of badchars.

    Operates on the lower 16 bits only. When the upper 16 bits of the parent
    register matter, zero it beforehand (e.g. 'xor eax, eax').
    """
    v_bytes = [(value >> (8 * i)) & 0xFF for i in range(2)]
    if not any(b in badchars for b in v_bytes):
        return [f"    mov  {reg}, 0x{value:04x}"]
    mask_bytes = [_find_mask_byte(b, badchars) for b in v_bytes]
    mask    = mask_bytes[0] | (mask_bytes[1] << 8)
    encoded = value ^ mask
    return [
        f"    mov  {reg}, 0x{encoded:04x}",
        f"    xor  {reg}, 0x{mask:04x}",
    ]


def safe_push_dword(value: int, badchars: set[int]) -> list[str]:
    """Emit a badchar-safe push of a 32-bit immediate via eax."""
    return [*encode_dword(value, badchars, "eax"), "    push eax"]


def safe_push_word_as_dword(value: int, badchars: set[int]) -> list[str]:
    """Emit a badchar-safe push of a 16-bit value zero-extended to 32 bits.

    Use for constants like MAKEWORD(2,2)=0x0202 which must be pushed as a
    DWORD but whose upper bytes would be null if encoded as push imm32.
    """
    return ["    xor  eax, eax", *encode_word(value, badchars, "ax"), "    push eax"]
