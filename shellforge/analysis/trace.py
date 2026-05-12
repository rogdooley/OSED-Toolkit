from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from shellforge.contracts.errors import ErrorCode, ShellforgeError

_PAGE_SIZE = 0x1000
_STACK_SIZE = 0x10000
_STACK_BASE = 0x70000000
_MAX_STEPS = 10000
_MAX_BLOB_SIZE = 0x200000


@dataclass(frozen=True, slots=True)
class TraceStep:
    index: int
    address: int
    bytes_hex: str
    mnemonic: str
    operands: str
    register_diff: dict[str, dict[str, str]]
    stack_pointer_before: int
    stack_pointer_after: int
    stack_delta: int
    call_depth: int
    notes: list[str]
    annotations: list[str]
    writes: list[dict[str, object]]
    stack_window: list[dict[str, object]]
    watched_registers: dict[str, str]


@dataclass(frozen=True, slots=True)
class TraceResult:
    arch: str
    base: int
    steps_requested: int
    steps_executed: int
    stopped_reason: str
    final_registers: dict[str, str]
    write_summary: dict[str, object]
    trace: list[TraceStep]


def _align_down(value: int, alignment: int) -> int:
    return value & ~(alignment - 1)


def _align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def _trace_register_layout(arch: str) -> tuple[list[tuple[str, int]], int, int]:
    try:
        from unicorn.x86_const import (
            UC_X86_REG_EAX,
            UC_X86_REG_EBP,
            UC_X86_REG_EBX,
            UC_X86_REG_ECX,
            UC_X86_REG_EDI,
            UC_X86_REG_EDX,
            UC_X86_REG_EIP,
            UC_X86_REG_ESI,
            UC_X86_REG_ESP,
            UC_X86_REG_RAX,
            UC_X86_REG_RBP,
            UC_X86_REG_RBX,
            UC_X86_REG_RCX,
            UC_X86_REG_RDI,
            UC_X86_REG_RDX,
            UC_X86_REG_RIP,
            UC_X86_REG_RSI,
            UC_X86_REG_RSP,
            UC_X86_REG_R8,
            UC_X86_REG_R9,
            UC_X86_REG_R10,
            UC_X86_REG_R11,
            UC_X86_REG_R12,
            UC_X86_REG_R13,
            UC_X86_REG_R14,
            UC_X86_REG_R15,
        )
    except Exception as exc:  # pragma: no cover
        raise ShellforgeError(
            ErrorCode.INTERNAL_ERROR,
            "unicorn dependency is required for trace",
            details={"exception_type": exc.__class__.__name__},
        ) from exc

    lowered = arch.lower()
    if lowered == "x86":
        regs = [
            ("eax", UC_X86_REG_EAX),
            ("ebx", UC_X86_REG_EBX),
            ("ecx", UC_X86_REG_ECX),
            ("edx", UC_X86_REG_EDX),
            ("esi", UC_X86_REG_ESI),
            ("edi", UC_X86_REG_EDI),
            ("ebp", UC_X86_REG_EBP),
            ("esp", UC_X86_REG_ESP),
            ("eip", UC_X86_REG_EIP),
        ]
        return regs, UC_X86_REG_EIP, UC_X86_REG_ESP
    if lowered == "x64":
        regs = [
            ("rax", UC_X86_REG_RAX),
            ("rbx", UC_X86_REG_RBX),
            ("rcx", UC_X86_REG_RCX),
            ("rdx", UC_X86_REG_RDX),
            ("rsi", UC_X86_REG_RSI),
            ("rdi", UC_X86_REG_RDI),
            ("rbp", UC_X86_REG_RBP),
            ("rsp", UC_X86_REG_RSP),
            ("r8", UC_X86_REG_R8),
            ("r9", UC_X86_REG_R9),
            ("r10", UC_X86_REG_R10),
            ("r11", UC_X86_REG_R11),
            ("r12", UC_X86_REG_R12),
            ("r13", UC_X86_REG_R13),
            ("r14", UC_X86_REG_R14),
            ("r15", UC_X86_REG_R15),
            ("rip", UC_X86_REG_RIP),
        ]
        return regs, UC_X86_REG_RIP, UC_X86_REG_RSP
    raise ShellforgeError(
        ErrorCode.INVALID_ARGUMENT,
        "unsupported architecture for trace",
        details={"arch": arch, "supported": ["x86", "x64"]},
    )


def _engine_for_arch(arch: str) -> tuple[Any, Any]:
    try:
        from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_MODE_64
    except Exception as exc:  # pragma: no cover
        raise ShellforgeError(
            ErrorCode.INTERNAL_ERROR,
            "unicorn dependency is required for trace",
            details={"exception_type": exc.__class__.__name__},
        ) from exc

    lowered = arch.lower()
    if lowered == "x86":
        return Uc(UC_ARCH_X86, UC_MODE_32), 4
    if lowered == "x64":
        return Uc(UC_ARCH_X86, UC_MODE_64), 8
    raise ShellforgeError(
        ErrorCode.INVALID_ARGUMENT,
        "unsupported architecture for trace",
        details={"arch": arch, "supported": ["x86", "x64"]},
    )


def _disasm_for_arch(arch: str) -> Any:
    try:
        from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs
    except Exception as exc:  # pragma: no cover
        raise ShellforgeError(
            ErrorCode.INTERNAL_ERROR,
            "capstone dependency is required for trace",
            details={"exception_type": exc.__class__.__name__},
        ) from exc

    lowered = arch.lower()
    if lowered == "x86":
        return Cs(CS_ARCH_X86, CS_MODE_32)
    if lowered == "x64":
        return Cs(CS_ARCH_X86, CS_MODE_64)
    raise ShellforgeError(
        ErrorCode.INVALID_ARGUMENT,
        "unsupported architecture for trace",
        details={"arch": arch, "supported": ["x86", "x64"]},
    )


def _classify_write(
    address: int, *, stack_start: int, stack_end: int, blob_start: int, blob_end: int, code_start: int, code_end: int
) -> str:
    if stack_start <= address < stack_end:
        return "stack"
    if blob_start <= address < blob_end:
        return "blob"
    if code_start <= address < code_end:
        return "code"
    return "unmapped"


def _stack_window_rows(uc: Any, sp: int, *, pointer_size: int, slots: int) -> list[dict[str, object]]:
    if slots <= 0:
        return []
    import struct

    fmt = "<I" if pointer_size == 4 else "<Q"
    rows: list[dict[str, object]] = []
    for idx in range(slots):
        addr = sp + (idx * pointer_size)
        raw = bytes(uc.mem_read(addr, pointer_size))
        value = struct.unpack(fmt, raw)[0]
        rows.append({"address": addr, "address_hex": f"0x{addr:x}", "value": value, "value_hex": f"0x{value:x}"})
    return rows


def _peb_annotations(arch: str, mnemonic: str, operands: str) -> list[str]:
    text = f"{mnemonic} {operands}".lower()
    annotations: list[str] = []
    if arch == "x86" and "fs:[" in text and ("0x30" in text or "30h" in text):
        annotations.append("accessing PEB")
    if arch == "x64" and "gs:[" in text and ("0x60" in text or "60h" in text):
        annotations.append("accessing PEB")
    if "+ 0xc" in text or "+0xc" in text:
        annotations.append("accessing PEB_LDR_DATA")
    if "+ 0x14" in text or "+0x14" in text:
        annotations.append("walking loader list (InMemoryOrderModuleList)")
    if "+ 0x1c" in text or "+0x1c" in text:
        annotations.append("walking loader list (InInitializationOrderModuleList)")
        annotations.append("likely kernel32 traversal")
    if "+ 0x3c" in text or "+0x3c" in text:
        annotations.append("reading PE header e_lfanew")
    if "+ 0x78" in text or "+0x78" in text:
        annotations.append("reading export directory")
    return annotations


def trace_bytes(
    data: bytes,
    *,
    arch: str = "x86",
    base: int = 0x1000,
    steps: int = 100,
    stack_window_slots: int = 0,
    watch_registers: list[str] | None = None,
    explain_peb: bool = False,
) -> TraceResult:
    if not data:
        raise ShellforgeError(ErrorCode.INVALID_ARGUMENT, "trace input cannot be empty")
    if len(data) > _MAX_BLOB_SIZE:
        raise ShellforgeError(
            ErrorCode.INVALID_ARGUMENT,
            "trace input exceeds maximum supported size",
            details={"size": len(data), "max_size": _MAX_BLOB_SIZE},
        )
    if base < 0:
        raise ShellforgeError(ErrorCode.INVALID_ARGUMENT, "base address must be non-negative", details={"base": base})
    if steps <= 0:
        raise ShellforgeError(ErrorCode.INVALID_ARGUMENT, "steps must be a positive integer", details={"steps": steps})
    if steps > _MAX_STEPS:
        raise ShellforgeError(
            ErrorCode.INVALID_ARGUMENT,
            "steps exceeds hard maximum",
            details={"steps": steps, "max_steps": _MAX_STEPS},
        )
    if stack_window_slots < 0:
        raise ShellforgeError(
            ErrorCode.INVALID_ARGUMENT,
            "stack-window must be non-negative",
            details={"stack_window": stack_window_slots},
        )

    uc, pointer_size = _engine_for_arch(arch)
    disasm = _disasm_for_arch(arch)
    reg_layout, pc_reg, sp_reg = _trace_register_layout(arch)
    regs_lookup = {name: reg_id for name, reg_id in reg_layout}
    watch_registers = [item.lower().strip() for item in (watch_registers or []) if item.strip()]
    for name in watch_registers:
        if name not in regs_lookup:
            raise ShellforgeError(
                ErrorCode.INVALID_ARGUMENT,
                "invalid watch register",
                details={"register": name, "supported": sorted(regs_lookup.keys())},
            )

    code_start = _align_down(base, _PAGE_SIZE)
    offset = base - code_start
    code_size = _align_up(offset + len(data), _PAGE_SIZE)
    code_end = base + len(data)
    stack_start = _align_down(_STACK_BASE, _PAGE_SIZE)
    stack_size = _align_up(_STACK_SIZE, _PAGE_SIZE)
    stack_end = stack_start + stack_size
    # Keep deterministic and ABI-friendly stack alignment.
    initial_sp = (stack_end - 0x100) & ~0xF

    uc.mem_map(code_start, code_size)
    uc.mem_write(base, data)
    uc.mem_map(stack_start, stack_size)

    for index, (_, reg_id) in enumerate(reg_layout):
        uc.reg_write(reg_id, 0x11110000 + index)
    uc.reg_write(pc_reg, base)
    uc.reg_write(sp_reg, initial_sp)

    try:
        from unicorn import UC_HOOK_MEM_WRITE
    except Exception as exc:  # pragma: no cover
        raise ShellforgeError(
            ErrorCode.INTERNAL_ERROR,
            "unicorn dependency is required for trace",
            details={"exception_type": exc.__class__.__name__},
        ) from exc

    steps_out: list[TraceStep] = []
    call_depth = 0
    stopped_reason = "completed"
    current_writes: list[dict[str, object]] = []
    write_by_class = {"stack": 0, "blob": 0, "code": 0, "unmapped": 0}
    total_writes = 0
    self_modifying_writes = 0

    def _on_mem_write(_uc, _access, address, size, value, _user_data):
        nonlocal total_writes, self_modifying_writes
        classification = _classify_write(
            int(address),
            stack_start=stack_start,
            stack_end=stack_end,
            blob_start=base,
            blob_end=code_end,
            code_start=code_start,
            code_end=code_start + code_size,
        )
        is_self_modifying = classification == "blob"
        if is_self_modifying:
            self_modifying_writes += 1
        write_by_class[classification] += 1
        total_writes += 1
        current_writes.append(
            {
                "address": int(address),
                "address_hex": f"0x{int(address):x}",
                "size": int(size),
                "value": int(value),
                "value_hex": f"0x{int(value):x}",
                "classification": classification,
                "self_modifying": is_self_modifying,
            }
        )

    uc.hook_add(UC_HOOK_MEM_WRITE, _on_mem_write)

    for idx in range(steps):
        pc_before = int(uc.reg_read(pc_reg))
        sp_before = int(uc.reg_read(sp_reg))
        if pc_before < base or pc_before >= code_end:
            stopped_reason = "execution_left_blob"
            break

        raw = bytes(uc.mem_read(pc_before, 15))
        decoded = next(disasm.disasm(raw, pc_before, count=1), None)
        if decoded is None or decoded.size <= 0:
            stopped_reason = "decode_error"
            break

        insn_bytes = bytes(decoded.bytes)
        mnemonic = decoded.mnemonic.lower()
        operands = decoded.op_str or ""
        notes: list[str] = []
        annotations = _peb_annotations(arch.lower(), mnemonic, operands) if explain_peb else []
        regs_before = {name: int(uc.reg_read(reg_id)) for name, reg_id in reg_layout}
        current_writes = []

        if mnemonic in {"syscall", "sysenter", "sysexit"} or (mnemonic == "int" and operands.strip().lower() == "0x2e"):
            stopped_reason = "syscall_blocked"
            notes.append("syscall/sysenter/int2e")
            steps_out.append(
                TraceStep(
                    index=idx,
                    address=pc_before,
                    bytes_hex=insn_bytes.hex(),
                    mnemonic=mnemonic,
                    operands=operands,
                    register_diff={},
                    stack_pointer_before=sp_before,
                    stack_pointer_after=sp_before,
                    stack_delta=0,
                    call_depth=call_depth,
                    notes=notes,
                    annotations=annotations,
                    writes=[],
                    stack_window=_stack_window_rows(uc, sp_before, pointer_size=pointer_size, slots=stack_window_slots),
                    watched_registers={name: f"0x{regs_before[name]:x}" for name in watch_registers},
                )
            )
            break

        if mnemonic in {"hlt", "cli", "sti", "in", "out", "iret", "iretd", "iretq", "rdmsr", "wrmsr"}:
            stopped_reason = "privileged_instruction"
            notes.append("privileged_instruction")
            steps_out.append(
                TraceStep(
                    index=idx,
                    address=pc_before,
                    bytes_hex=insn_bytes.hex(),
                    mnemonic=mnemonic,
                    operands=operands,
                    register_diff={},
                    stack_pointer_before=sp_before,
                    stack_pointer_after=sp_before,
                    stack_delta=0,
                    call_depth=call_depth,
                    notes=notes,
                    annotations=annotations,
                    writes=[],
                    stack_window=_stack_window_rows(uc, sp_before, pointer_size=pointer_size, slots=stack_window_slots),
                    watched_registers={name: f"0x{regs_before[name]:x}" for name in watch_registers},
                )
            )
            break

        try:
            uc.emu_start(pc_before, code_end, count=1)
        except Exception as exc:
            message = str(exc).lower()
            stopped_reason = "emulator_error"
            if "unmapped" in message:
                stopped_reason = "unmapped_memory"
                if mnemonic in {"ret", "retf"}:
                    stopped_reason = "ret_unmapped_target"
            notes.append(stopped_reason)
            steps_out.append(
                TraceStep(
                    index=idx,
                    address=pc_before,
                    bytes_hex=insn_bytes.hex(),
                    mnemonic=mnemonic,
                    operands=operands,
                    register_diff={},
                    stack_pointer_before=sp_before,
                    stack_pointer_after=int(uc.reg_read(sp_reg)),
                    stack_delta=int(uc.reg_read(sp_reg)) - sp_before,
                    call_depth=call_depth,
                    notes=notes,
                    annotations=annotations,
                    writes=current_writes,
                    stack_window=_stack_window_rows(
                        uc, int(uc.reg_read(sp_reg)), pointer_size=pointer_size, slots=stack_window_slots
                    ),
                    watched_registers={
                        name: f"0x{int(uc.reg_read(regs_lookup[name])):x}" for name in watch_registers
                    },
                )
            )
            break

        regs_after = {name: int(uc.reg_read(reg_id)) for name, reg_id in reg_layout}
        pc_after = int(uc.reg_read(pc_reg))
        sp_after = int(uc.reg_read(sp_reg))
        stack_delta = sp_after - sp_before

        if mnemonic == "call":
            call_depth += 1
            notes.append("call")
        elif mnemonic in {"ret", "retf"}:
            notes.append("ret")
            call_depth = max(call_depth - 1, 0)
        elif mnemonic == "push":
            notes.append("push")
        elif mnemonic == "pop":
            notes.append("pop")
        elif mnemonic == "jmp":
            notes.append("jmp")
        elif mnemonic.startswith("loop"):
            notes.append("loop")

        if sp_after < stack_start or sp_after >= stack_end:
            notes.append("stack_underflow")
            stopped_reason = "stack_underflow"

        if abs(stack_delta) > pointer_size * 8 and mnemonic not in {"push", "pop", "call", "ret", "retf"}:
            notes.append("stack_pivot")
        if pc_after < base or pc_after >= code_end:
            notes.append("execution_left_blob")
            stopped_reason = "execution_left_blob"

        reg_diff: dict[str, dict[str, str]] = {}
        for name, before_value in regs_before.items():
            after_value = regs_after[name]
            if before_value == after_value:
                continue
            reg_diff[name] = {"before": f"0x{before_value:x}", "after": f"0x{after_value:x}"}

        steps_out.append(
            TraceStep(
                index=idx,
                address=pc_before,
                bytes_hex=insn_bytes.hex(),
                mnemonic=mnemonic,
                operands=operands,
                register_diff=reg_diff,
                stack_pointer_before=sp_before,
                stack_pointer_after=sp_after,
                stack_delta=stack_delta,
                call_depth=call_depth,
                notes=notes,
                annotations=annotations,
                writes=current_writes,
                stack_window=_stack_window_rows(uc, sp_after, pointer_size=pointer_size, slots=stack_window_slots),
                watched_registers={name: f"0x{regs_after[name]:x}" for name in watch_registers},
            )
        )

        if stopped_reason != "completed":
            break
    else:
        stopped_reason = "max_steps_reached"

    final_registers = {name: f"0x{int(uc.reg_read(reg_id)):x}" for name, reg_id in reg_layout if name in regs_lookup}
    return TraceResult(
        arch=arch.lower(),
        base=base,
        steps_requested=steps,
        steps_executed=len(steps_out),
        stopped_reason=stopped_reason,
        final_registers=final_registers,
        write_summary={
            "total_writes": total_writes,
            "self_modifying_writes": self_modifying_writes,
            "by_class": write_by_class,
        },
        trace=steps_out,
    )
