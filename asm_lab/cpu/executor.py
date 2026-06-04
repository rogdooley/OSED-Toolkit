"""Fixture-driven minimal executor for ASM-Lab."""

from __future__ import annotations

from dataclasses import dataclass

from asm_lab.models import (
    ByteSequence,
    ExecutionResult,
    ExecutionTrace,
    GoldenLessonFixture,
    MachineState,
    MemoryRead,
    MemoryDiff,
    MemoryRegion,
    MemoryWrite,
    RegisterChange,
    RegisterDiff,
    RegisterState,
    StackChange,
    StackDiff,
    StateDiff,
    Width,
)


@dataclass(frozen=True)
class _ParsedInstruction:
    opcode: str
    operands: list[str]


class MinimalExecutor:
    """Executes only the operand forms required by current reference fixtures."""

    def execute_instruction(self, state: MachineState, instruction: str) -> ExecutionResult:
        before_state = state.model_copy(deep=True)
        parsed = self._parse_instruction(instruction)
        registers = _register_map(before_state)
        memory = _memory_map(before_state)
        window_size = _stack_window_size(before_state)

        if parsed.opcode == "xor":
            after_state, trace, diff = self._execute_xor(before_state, registers, memory, window_size, parsed)
        elif parsed.opcode == "push":
            after_state, trace, diff = self._execute_push(before_state, registers, memory, window_size, parsed)
        elif parsed.opcode == "mov":
            after_state, trace, diff = self._execute_mov(before_state, registers, memory, window_size, parsed)
        elif parsed.opcode == "sub":
            after_state, trace, diff = self._execute_sub(before_state, registers, memory, window_size, parsed)
        else:
            raise ValueError(f"Unsupported opcode for minimal executor: {parsed.opcode}")

        return ExecutionResult(
            before_state=before_state,
            after_state=after_state,
            execution_trace=trace,
            state_diff=diff,
        )

    def _execute_xor(
        self,
        before_state: MachineState,
        registers: dict[str, int],
        memory: dict[int, int],
        window_size: int,
        parsed: _ParsedInstruction,
    ) -> tuple[MachineState, ExecutionTrace, StateDiff]:
        left, right = parsed.operands
        if left != right or left != "eax":
            raise ValueError("Minimal executor only supports 'xor eax, eax'.")

        before_value = registers["eax"]
        registers["eax"] = 0
        registers["eip"] += 2

        after_state = _build_state(before_state, registers, memory, window_size)
        register_change = RegisterChange(
            register_name="eax",
            before=before_value,
            after=0,
            width_bits=32,
        )
        register_diff = RegisterDiff(
            register_name="eax",
            before=before_value,
            after=0,
            width_bits=32,
        )
        diff = StateDiff(register_diffs=[register_diff])
        trace = ExecutionTrace(
            instruction="xor eax, eax",
            operands=["eax", "eax"],
            register_changes=[register_change],
            state_diff=diff,
            notes=["Register-only transition."],
        )
        return after_state, trace, diff

    def _execute_push(
        self,
        before_state: MachineState,
        registers: dict[str, int],
        memory: dict[int, int],
        window_size: int,
        parsed: _ParsedInstruction,
    ) -> tuple[MachineState, ExecutionTrace, StateDiff]:
        operand = parsed.operands[0]
        before_esp = registers["esp"]
        value, pushed_bytes, instruction_size = self._resolve_push_operand(registers, operand)
        after_esp = before_esp - 4
        before_bytes = ByteSequence(
            data=bytes(memory.get(after_esp + offset, 0) for offset in range(4))
        )

        for offset, byte_value in enumerate(pushed_bytes.data):
            memory[after_esp + offset] = byte_value

        registers["esp"] = after_esp
        registers["eip"] += instruction_size
        after_state = _build_state(before_state, registers, memory, window_size)

        memory_write = MemoryWrite(
            address=after_esp,
            before_bytes=before_bytes,
            after_bytes=pushed_bytes,
            width=Width.DWORD,
        )
        stack_change = StackChange(
            stack_pointer_register="esp",
            before=before_esp,
            after=after_esp,
            pushed_bytes=pushed_bytes,
            popped_bytes=ByteSequence(),
        )
        memory_diff = MemoryDiff(
            address=after_esp,
            before_bytes=before_bytes,
            after_bytes=pushed_bytes,
            width=Width.DWORD,
        )
        stack_diff = StackDiff(
            stack_pointer_register="esp",
            before=before_esp,
            after=after_esp,
            pushed_bytes=pushed_bytes,
            popped_bytes=ByteSequence(),
        )
        diff = StateDiff(memory_diffs=[memory_diff], stack_diffs=[stack_diff])
        trace = ExecutionTrace(
            instruction=f"push {operand}",
            operands=[operand],
            writes=[memory_write],
            stack_changes=[stack_change],
            state_diff=diff,
        )
        return after_state, trace, diff

    def _resolve_push_operand(
        self, registers: dict[str, int], operand: str
    ) -> tuple[int, ByteSequence, int]:
        normalized = operand.lower()
        if normalized.startswith("0x"):
            value = int(normalized, 16)
            return value, ByteSequence(data=value.to_bytes(4, "little", signed=False)), 5
        _require_reg32(normalized)
        value = registers[normalized]
        return value, ByteSequence(data=value.to_bytes(4, "little", signed=False)), 1

    def _parse_instruction(self, instruction: str) -> _ParsedInstruction:
        opcode, *rest = instruction.strip().split(maxsplit=1)
        operands = []
        if rest:
            operands = [operand.strip() for operand in rest[0].split(",")]
        return _ParsedInstruction(opcode=opcode.lower(), operands=operands)

    def _execute_mov(
        self,
        before_state: MachineState,
        registers: dict[str, int],
        memory: dict[int, int],
        window_size: int,
        parsed: _ParsedInstruction,
    ) -> tuple[MachineState, ExecutionTrace, StateDiff]:
        destination, source = parsed.operands
        _require_reg32(destination)
        before_value = registers[destination]

        reads = []
        notes: list[str] = []
        if source.startswith("0x"):
            after_value = int(source, 16)
            instruction_size = 5
            notes.append("Immediate value loaded into a general-purpose register.")
        elif source.startswith("[") and source.endswith("]"):
            source_register = source[1:-1].strip().lower()
            _require_reg32(source_register)
            address = registers[source_register]
            read_bytes = ByteSequence(
                data=bytes(memory.get(address + offset, 0) for offset in range(4))
            )
            after_value = read_bytes.to_little_endian_int()
            instruction_size = 2
            reads = [
                MemoryRead(
                    address=address,
                    bytes_value=read_bytes,
                    width=Width.DWORD,
                    pointer_source=source_register,
                )
            ]
        elif source.lower() in {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"}:
            source_register = source.lower()
            _require_reg32(source_register)
            after_value = registers[source_register]
            instruction_size = 2
        else:
            raise ValueError(
                "Minimal executor only supports 'mov reg32, imm32', 'mov reg32, reg32', and 'mov reg32, [reg32]'."
            )

        registers[destination] = after_value
        registers["eip"] += instruction_size
        after_state = _build_state(before_state, registers, memory, window_size)
        register_change = RegisterChange(
            register_name=destination,
            before=before_value,
            after=after_value,
            width_bits=32,
        )
        register_diff = RegisterDiff(
            register_name=destination,
            before=before_value,
            after=after_value,
            width_bits=32,
        )
        diff = StateDiff(register_diffs=[register_diff])
        trace = ExecutionTrace(
            instruction=f"mov {destination}, {source}",
            operands=[destination, source],
            reads=reads,
            register_changes=[register_change],
            state_diff=diff,
            notes=notes,
        )
        return after_state, trace, diff


    def _execute_sub(
        self,
        before_state: MachineState,
        registers: dict[str, int],
        memory: dict[int, int],
        window_size: int,
        parsed: _ParsedInstruction,
    ) -> tuple[MachineState, ExecutionTrace, StateDiff]:
        destination, source = parsed.operands
        _require_reg32(destination)
        if not source.startswith("0x"):
            raise ValueError("Minimal executor only supports 'sub reg32, imm32'.")

        immediate = int(source, 16)
        before_value = registers[destination]
        after_value = (before_value - immediate) & 0xFFFFFFFF
        registers[destination] = after_value
        registers["eip"] += 3

        after_state = _build_state(before_state, registers, memory, window_size)
        register_change = RegisterChange(
            register_name=destination,
            before=before_value,
            after=after_value,
            width_bits=32,
        )
        register_diff = RegisterDiff(
            register_name=destination,
            before=before_value,
            after=after_value,
            width_bits=32,
        )
        stack_changes: list[StackChange] = []
        stack_diffs: list[StackDiff] = []
        if destination == "esp":
            stack_change = StackChange(
                stack_pointer_register="esp",
                before=before_value,
                after=after_value,
                pushed_bytes=ByteSequence(),
                popped_bytes=ByteSequence(),
            )
            stack_diff = StackDiff(
                stack_pointer_register="esp",
                before=before_value,
                after=after_value,
                pushed_bytes=ByteSequence(),
                popped_bytes=ByteSequence(),
            )
            stack_changes.append(stack_change)
            stack_diffs.append(stack_diff)

        diff = StateDiff(register_diffs=[register_diff], stack_diffs=stack_diffs)
        trace = ExecutionTrace(
            instruction=f"sub {destination}, {source}",
            operands=[destination, source],
            register_changes=[register_change],
            stack_changes=stack_changes,
            state_diff=diff,
        )
        return after_state, trace, diff



def run_fixture(
    fixture: GoldenLessonFixture,
    executor: MinimalExecutor,
) -> list[ExecutionResult]:
    """Run a hand-authored fixture step-by-step through the executor."""
    results: list[ExecutionResult] = []
    current_state = fixture.initial_state

    for step in fixture.steps:
        result = executor.execute_instruction(current_state, step.instruction)
        results.append(result)
        current_state = result.after_state

    return results


def _register_map(state: MachineState) -> dict[str, int]:
    return {register.name.lower(): register.value for register in state.registers}


def _memory_map(state: MachineState) -> dict[int, int]:
    memory: dict[int, int] = {}
    for region in state.memory_regions:
        for offset, byte_value in enumerate(region.bytes_value.data):
            memory[region.start_address + offset] = byte_value
    return memory


def _stack_window_size(state: MachineState) -> int:
    if not state.memory_regions:
        return 0
    return len(state.memory_regions[0].bytes_value)


def _build_state(
    template: MachineState,
    registers: dict[str, int],
    memory: dict[int, int],
    window_size: int,
) -> MachineState:
    regions = []
    esp = registers.get("esp", 0)
    for region in template.memory_regions:
        region_start = region.start_address
        if region.label == "stack-window":
            region_start = min(region.start_address, esp)
        regions.append(
            MemoryRegion(
                start_address=region_start,
                bytes_value=ByteSequence(
                    data=bytes(
                        memory.get(region_start + offset, 0)
                        for offset in range(len(region.bytes_value))
                    )
                ),
                label=region.label,
            )
        )
    updated_registers = [
        RegisterState(
            name=register.name,
            width_bits=register.width_bits,
            value=registers[register.name.lower()],
        )
        for register in template.registers
    ]
    return MachineState(
        architecture=template.architecture,
        registers=updated_registers,
        memory_regions=regions,
        stack_pointer_register=template.stack_pointer_register,
        instruction_pointer_register=template.instruction_pointer_register,
        annotations=[],
    )


def _require_reg32(register_name: str) -> None:
    allowed = {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"}
    if register_name.lower() not in allowed:
        raise ValueError(f"Unsupported reg32 operand for minimal executor: {register_name}")
