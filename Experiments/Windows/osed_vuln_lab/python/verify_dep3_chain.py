"""Simulate the DEP-3 ROP chain register state and verify the PUSHAD frame.

Walks a packed stage2 chain DWORD-by-DWORD, interpreting each gadget
address through a supplied gadget map, tracking register clobbers,
and asserting the final register state produces a valid VirtualProtect
call frame after PUSHAD.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from struct import unpack_from


@dataclass
class Regs:
    eax: int = 0
    ecx: int = 0
    edx: int = 0
    ebx: int = 0
    esp: int = 0
    ebp: int = 0
    esi: int = 0
    edi: int = 0


class ChainError(RuntimeError):
    pass


@dataclass
class Dep3ChainVerifier:
    gadget_map: dict[int, str]
    memory: dict[int, int] = field(default_factory=dict)

    def _pop(self, chain: bytes, offset: int) -> tuple[int, int]:
        if offset + 4 > len(chain):
            raise ChainError(f"chain underflow at offset {offset}")
        return unpack_from("<I", chain, offset)[0], offset + 4

    def execute(self, chain: bytes) -> Regs:
        regs = Regs()
        offset = 0
        while offset < len(chain):
            addr, offset = self._pop(chain, offset)
            gadget = self.gadget_map.get(addr)
            if gadget is None:
                raise ChainError(
                    f"unknown gadget address 0x{addr:08X} at chain offset {offset - 4}"
                )
            offset = self._dispatch(gadget, regs, chain, offset)
        return regs

    def _dispatch(self, gadget: str, r: Regs, chain: bytes, off: int) -> int:
        if gadget == "pop_eax;ret":
            r.eax, off = self._pop(chain, off)
        elif gadget == "pop_ecx;pop_ebp;pop_edi;pop_eax;ret":
            r.ecx, off = self._pop(chain, off)
            r.ebp, off = self._pop(chain, off)
            r.edi, off = self._pop(chain, off)
            r.eax, off = self._pop(chain, off)
        elif gadget == "xchg_eax_edx;ret":
            r.eax, r.edx = r.edx, r.eax
        elif gadget == "pop_ebx;pop_ebp;pop_eax;ret":
            r.ebx, off = self._pop(chain, off)
            r.ebp, off = self._pop(chain, off)
            r.eax, off = self._pop(chain, off)
        elif gadget == "pop_ebp;ret":
            r.ebp, off = self._pop(chain, off)
        elif gadget == "neg_eax;ret":
            r.eax = (-r.eax) & 0xFFFFFFFF
        elif gadget == "deref_eax_plus_10;ret":
            addr = (r.eax + 0x10) & 0xFFFFFFFF
            if addr not in self.memory:
                raise ChainError(
                    f"dereference of unmapped address 0x{addr:08X} "
                    f"(eax=0x{r.eax:08X} + 0x10)"
                )
            r.eax = self.memory[addr]
        elif gadget == "xchg_eax_ebx;ret":
            r.eax, r.ebx = r.ebx, r.eax
        elif gadget == "xchg_eax_esi;ret":
            r.eax, r.esi = r.esi, r.eax
        elif gadget == "add_esp_0x1c;ret":
            skip = 0x1C
            if off + skip > len(chain):
                raise ChainError(f"add esp, 0x1c overflows chain at offset {off}")
            off += skip
        elif gadget == "pushad":
            pass
        elif gadget == "ret":
            pass
        elif gadget == "mov_[esi]_eax;ret":
            self.memory[r.esi] = r.eax
        else:
            raise ChainError(f"unhandled gadget mnemonic: {gadget}")
        return off


@dataclass(frozen=True)
class PushadFrame:
    edi: int
    esi: int
    ebp: int
    ebx: int
    edx: int
    ecx: int


def verify_pushad_frame(
    regs: Regs,
    *,
    expected_esi: int,
    expected_ebp: int,
    expected_ebx: int,
    expected_edx: int,
    expected_ecx: int,
    ret_gadget: int,
) -> list[str]:
    errors: list[str] = []
    if regs.edi != ret_gadget:
        errors.append(
            f"EDI=0x{regs.edi:08X} should be RET gadget 0x{ret_gadget:08X}"
        )
    if regs.esi != expected_esi:
        errors.append(
            f"ESI=0x{regs.esi:08X} should be VirtualProtect 0x{expected_esi:08X}"
        )
    if regs.ebp != expected_ebp:
        errors.append(
            f"EBP=0x{regs.ebp:08X} should be return address 0x{expected_ebp:08X}"
        )
    if regs.ebx != expected_ebx:
        errors.append(
            f"EBX=0x{regs.ebx:08X} should be region size 0x{expected_ebx:08X}"
        )
    if regs.edx != expected_edx:
        errors.append(
            f"EDX=0x{regs.edx:08X} should be PAGE_EXECUTE_READWRITE 0x{expected_edx:08X}"
        )
    if regs.ecx != expected_ecx:
        errors.append(
            f"ECX=0x{regs.ecx:08X} should be old protect address 0x{expected_ecx:08X}"
        )
    return errors
