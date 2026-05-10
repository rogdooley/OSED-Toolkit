from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from shellforge.analysis.entropy import shannon_entropy
from shellforge.analysis.printable import printable_ratio
from shellforge.contracts.errors import ErrorCode, ShellforgeError

@dataclass(frozen=True, slots=True)
class DisasmInstruction:
    address: int
    bytes_hex: str
    mnemonic: str
    operands: str


@dataclass(frozen=True, slots=True)
class DisasmMetadata:
    entropy: float
    printable_ratio: float
    null_byte_count: int
    size: int


@dataclass(frozen=True, slots=True)
class DisasmResult:
    arch: str
    base: int
    instructions: list[DisasmInstruction]
    metadata: DisasmMetadata


def _engine_for_arch(arch: str) -> Any:
    try:
        from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs
    except Exception as exc:  # pragma: no cover
        raise ShellforgeError(
            ErrorCode.INTERNAL_ERROR,
            "capstone dependency is required for disasm",
            details={"exception_type": exc.__class__.__name__},
        ) from exc

    lowered = arch.lower()
    if lowered == "x86":
        return Cs(CS_ARCH_X86, CS_MODE_32)
    if lowered == "x64":
        return Cs(CS_ARCH_X86, CS_MODE_64)
    raise ShellforgeError(
        ErrorCode.INVALID_ARGUMENT,
        "unsupported architecture for disassembly",
        details={"arch": arch, "supported": ["x86", "x64"]},
    )


def disassemble_bytes(data: bytes, *, arch: str = "x86", base: int = 0) -> DisasmResult:
    if base < 0:
        raise ShellforgeError(
            ErrorCode.INVALID_ARGUMENT,
            "base address must be non-negative",
            details={"base": base},
        )

    md = _engine_for_arch(arch)
    instructions: list[DisasmInstruction] = []
    for insn in md.disasm(data, base):
        instructions.append(
            DisasmInstruction(
                address=insn.address,
                bytes_hex=insn.bytes.hex(),
                mnemonic=insn.mnemonic,
                operands=insn.op_str or "",
            )
        )

    meta = DisasmMetadata(
        entropy=shannon_entropy(data),
        printable_ratio=printable_ratio(data),
        null_byte_count=data.count(0),
        size=len(data),
    )
    return DisasmResult(arch=arch.lower(), base=base, instructions=instructions, metadata=meta)
