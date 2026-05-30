"""
Symbolic chain element types, Gadget, and ValidationIssue.

ChainElement is a union of five concrete types that represent everything that
can appear in a ROP chain before addresses are resolved:

    RawDword      — literal 32-bit constant (flag, size, etc.)
    GadgetRef     — named gadget resolved from GadgetDB at serialization
    WritablePtr   — named writable memory location (e.g. lpflOldProtect)
    ShellcodePtr  — placeholder for the runtime shellcode base address
    PaddingBlock  — one or more consecutive filler dwords
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Literal


# ── Symbolic chain elements ──────────────────────────────────────────────────


@dataclass(frozen=True)
class RawDword:
    """A literal 32-bit value pushed directly onto the chain."""

    value: int
    purpose: str = ""

    def __post_init__(self) -> None:
        if not (0 <= self.value <= 0xFFFFFFFF):
            raise ValueError(
                f"RawDword value {self.value!r} is outside the 32-bit range"
            )


@dataclass(frozen=True)
class GadgetRef:
    """
    Reference to a named gadget whose address is resolved from GadgetDB.

    The *name* is a key in the JSON gadget database, e.g. ``"pop_eax_ret"``.
    """

    name: str
    purpose: str = ""


@dataclass(frozen=True)
class WritablePtr:
    """
    Named writable memory location — resolved the same way as a GadgetRef but
    carries a distinct type so validators can check it separately.

    Typically used for VirtualProtect's *lpflOldProtect* argument.
    """

    name: str
    purpose: str = ""


@dataclass(frozen=True)
class ShellcodePtr:
    """
    Placeholder for the runtime shellcode base address.

    Must be supplied to ChainSerializer.serialize() via *shellcode_addr*.
    """

    purpose: str = "shellcode address"


@dataclass(frozen=True)
class PaddingBlock:
    """One or more consecutive dword-sized filler entries."""

    count: int
    value: int = 0x41414141
    purpose: str = "padding"

    def __post_init__(self) -> None:
        if self.count < 1:
            raise ValueError(
                f"PaddingBlock.count must be >= 1, got {self.count}"
            )
        if not (0 <= self.value <= 0xFFFFFFFF):
            raise ValueError(
                f"PaddingBlock.value {self.value!r} is outside the 32-bit range"
            )


# Python 3.12 type alias
type ChainElement = RawDword | GadgetRef | WritablePtr | ShellcodePtr | PaddingBlock


# ── Gadget record ────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Gadget:
    """One entry loaded from the gadget database."""

    address: int
    module: str
    instruction: str  # human-readable, e.g. "pop eax; ret"

    def pack(self) -> bytes:
        """Little-endian 4-byte representation of the gadget address."""
        return struct.pack("<I", self.address)


# ── Validation output ────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ValidationIssue:
    severity: Literal["error", "warning"]
    code: str
    message: str
    element_index: int | None = None

    def __str__(self) -> str:
        loc = (
            f" [element {self.element_index}]"
            if self.element_index is not None
            else ""
        )
        return f"[{self.severity.upper()}]{loc} {self.code}: {self.message}"
