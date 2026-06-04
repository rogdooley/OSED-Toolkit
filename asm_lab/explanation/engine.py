"""Deterministic explanation builders for milestone-two foundation."""

from __future__ import annotations

from asm_lab.models import (
    ByteSequence,
    ExecutionTrace,
    Explanation,
    ExplanationEntry,
    StateDiff,
)


class ExplanationEngine:
    """Builds deterministic explanations from execution traces and state diffs."""

    def build_explanation(self, trace: ExecutionTrace, state_diff: StateDiff) -> Explanation:
        instruction_name = trace.instruction.strip().split(maxsplit=1)[0].lower()
        builder = {
            "mov": self._build_mov_explanation,
            "push": self._build_push_explanation,
            "sub": self._build_sub_explanation,
            "xor": self._build_xor_explanation,
        }.get(instruction_name, self._build_generic_explanation)
        return builder(trace, state_diff)

    def _build_mov_explanation(self, trace: ExecutionTrace, state_diff: StateDiff) -> Explanation:
        changed_registers = trace.register_changes
        memory_reads = trace.reads
        what_changed = []
        why = []
        interpretation = []
        shellcode_relevance = []

        if changed_registers:
            register_change = changed_registers[0]
            if memory_reads:
                what_changed.append(
                    ExplanationEntry(
                        key="register_updated_from_memory",
                        label="Register Updated From Memory",
                        text=(
                            f"{register_change.register_name.upper()} was updated from "
                            "bytes read through a pointer dereference."
                        ),
                    )
                )
            else:
                what_changed.append(
                    ExplanationEntry(
                        key="register.updated",
                        label="Register Updated",
                        text=(
                            f"{register_change.register_name.upper()} changed from "
                            f"{register_change.before:#010x} to {register_change.after:#010x}."
                        ),
                    )
                )
        if memory_reads:
            read = memory_reads[0]
            what_changed.append(
                ExplanationEntry(
                    key="memory_read",
                    label="Memory Read",
                    text=(
                        f"Bytes were read from {read.address:#x}: {read.bytes_value.to_hex()}."
                    ),
                )
            )
            why.append(
                ExplanationEntry(
                    key="pointer_dereference",
                    label="Pointer Dereference",
                    text=(
                        f"[{read.pointer_source.upper()}] triggered a memory read from "
                        f"{read.address:#x}."
                    ),
                )
            )
            interpretation.append(
                ExplanationEntry(
                    key="address_vs_value",
                    label="Address Versus Value",
                    text=(
                        f"{read.pointer_source.upper()} holds the address {read.address:#x}. "
                        "The bytes at that location are a separate value loaded into the destination register."
                    ),
                )
            )
            interpretation.append(
                ExplanationEntry(
                    key="little_endian_interpretation",
                    label="Little-Endian Interpretation",
                    text=(
                        f"The bytes {read.bytes_value.to_hex()} become "
                        f"{read.bytes_value.to_little_endian_int():#x} when interpreted as a DWORD."
                    ),
                )
            )
            shellcode_relevance.append(
                ExplanationEntry(
                    key="pointer_dereference",
                    label="Pointer Dereference",
                    text=(
                        "Shellcode frequently follows pointers to reach strings, "
                        "structures, and API-related data."
                    ),
                )
            )

        elif changed_registers:
            register_change = changed_registers[0]
            if trace.operands == ["ebp", "esp"]:
                what_changed.append(
                    ExplanationEntry(
                        key="register.updated",
                        label="Register Updated",
                        text=(
                            f"{register_change.register_name.upper()} changed from "
                            f"{register_change.before:#010x} to {register_change.after:#010x}."
                        ),
                    )
                )
                why.append(
                    ExplanationEntry(
                        key="frame_pointer_established",
                        label="Frame Pointer Established",
                        text="Copying ESP into EBP makes EBP the stable reference point for this stack frame.",
                    )
                )
                interpretation.extend(
                    [
                        ExplanationEntry(
                            key="return_address_location",
                            label="Return Address Location",
                            text="Once EBP is established, [EBP+4] identifies the caller's return address.",
                        ),
                        ExplanationEntry(
                            key="argument_location",
                            label="Argument Location",
                            text="Once EBP is established, [EBP+8] identifies the first stack argument.",
                        ),
                    ]
                )
            else:
                why.extend(
                    [
                        ExplanationEntry(
                            key="pointer_setup",
                            label="Pointer Setup",
                            text=(
                                f"{register_change.register_name.upper()} was loaded with "
                                f"{register_change.after:#010x} so it can be used as an address."
                            ),
                        ),
                        ExplanationEntry(
                            key="address_vs_value",
                            label="Address Versus Value",
                            text=(
                                f"{register_change.register_name.upper()} contains the value "
                                f"{register_change.after:#010x}. ASM-Lab interprets this value as an address, "
                                "not as the bytes stored at that location."
                            ),
                        ),
                    ]
                )
                interpretation.extend(
                    [
                        ExplanationEntry(
                            key="address_vs_value",
                            label="Address Versus Value",
                            text=(
                                f"{register_change.after:#010x} names a location in memory. "
                                "It is not the string or DWORD stored there."
                            ),
                        ),
                        ExplanationEntry(
                            key="pointer_setup",
                            label="Pointer Setup",
                            text="The register now serves as a pointer to a known memory region.",
                        ),
                    ]
                )
                shellcode_relevance.append(
                    ExplanationEntry(
                        key="pointer_setup",
                        label="Pointer Setup",
                        text=(
                            "Shellcode often prepares registers as pointers before following them "
                            "to strings or structures."
                        ),
                    )
                )

        return self._assemble_explanation(trace, what_changed, why, interpretation, shellcode_relevance)

    def _build_push_explanation(self, trace: ExecutionTrace, state_diff: StateDiff) -> Explanation:
        what_changed = []
        why = []
        interpretation = []
        shellcode_relevance = []

        stack_change = trace.stack_changes[0] if trace.stack_changes else None
        memory_write = trace.writes[0] if trace.writes else None
        is_frame_setup = trace.operands == ["ebp"]

        if stack_change is not None:
            what_changed.append(
                ExplanationEntry(
                    key="stack.pointer_moved",
                    label="Stack Pointer Moved",
                    text=(
                        f"{stack_change.stack_pointer_register.upper()} moved from "
                        f"{stack_change.before:#010x} to {stack_change.after:#010x}."
                    ),
                )
            )
            why.append(
                ExplanationEntry(
                    key="stack_growth" if is_frame_setup else "push.grows_down",
                    label="Stack Growth",
                    text="A push stores data on the stack and moves the stack pointer downward.",
                )
            )
            if is_frame_setup:
                why.append(
                    ExplanationEntry(
                        key="frame_setup",
                        label="Frame Setup",
                        text="The current frame pointer is preserved before establishing a new stack frame.",
                    )
                )

        if memory_write is not None:
            what_changed.append(
                ExplanationEntry(
                    key="stack.memory_written",
                    label="Stack Write",
                    text=(
                        f"Stack memory at {memory_write.address:#x} was written with "
                        f"{memory_write.after_bytes.to_hex()}."
                    ),
                )
            )
            if is_frame_setup:
                interpretation.append(
                    ExplanationEntry(
                        key="saved_frame_pointer",
                        label="Saved Frame Pointer",
                        text="The pushed DWORD is the caller's EBP value, which becomes the saved frame pointer.",
                    )
                )
            else:
                interpretation.extend(self._build_interpretation_entries(memory_write.after_bytes))
                shellcode_relevance.append(
                    ExplanationEntry(
                        key="stack_string_construction",
                        label="Stack String Construction",
                        text=(
                            "Shellcode often pushes immediate values onto the stack to build "
                            "strings without relying on static data."
                        ),
                    )
                )

        return self._assemble_explanation(
            trace,
            what_changed,
            why,
            interpretation,
            shellcode_relevance,
        )

    def _build_sub_explanation(self, trace: ExecutionTrace, state_diff: StateDiff) -> Explanation:
        what_changed = []
        why = []
        interpretation = []
        shellcode_relevance = []

        register_change = trace.register_changes[0] if trace.register_changes else None
        stack_change = trace.stack_changes[0] if trace.stack_changes else None
        if register_change is not None:
            what_changed.append(
                ExplanationEntry(
                    key="register.updated",
                    label="Register Updated",
                    text=(
                        f"{register_change.register_name.upper()} changed from "
                        f"{register_change.before:#010x} to {register_change.after:#010x}."
                    ),
                )
            )
        if stack_change is not None:
            why.append(
                ExplanationEntry(
                    key="stack_growth",
                    label="Stack Growth",
                    text="Subtracting from ESP grows the stack downward and reserves space below EBP.",
                )
            )
        why.append(
            ExplanationEntry(
                key="local_storage_allocated",
                label="Local Storage Allocated",
                text="The subtraction reserves stack space that can be used for local variables.",
            )
        )
        interpretation.extend(
            [
                ExplanationEntry(
                    key="local_storage_allocated",
                    label="Local Storage Allocated",
                    text="Addresses below EBP now belong to the current function's local storage area.",
                ),
                ExplanationEntry(
                    key="saved_frame_pointer",
                    label="Saved Frame Pointer",
                    text="[EBP] still identifies the saved caller frame pointer at the top of the new frame.",
                ),
                ExplanationEntry(
                    key="return_address_location",
                    label="Return Address Location",
                    text="[EBP+4] identifies the return address that execution will use when the function exits.",
                ),
                ExplanationEntry(
                    key="argument_location",
                    label="Argument Location",
                    text="[EBP+8] identifies the first stack argument in this canonical frame layout.",
                ),
            ]
        )
        return self._assemble_explanation(
            trace,
            what_changed,
            why,
            interpretation,
            shellcode_relevance,
        )



    def _build_xor_explanation(self, trace: ExecutionTrace, state_diff: StateDiff) -> Explanation:
        what_changed = []
        why = []
        interpretation = []
        shellcode_relevance = []

        register_change = trace.register_changes[0] if trace.register_changes else None
        if register_change is not None:
            what_changed.append(
                ExplanationEntry(
                    key="register.updated",
                    label="Register Updated",
                    text=(
                        f"{register_change.register_name.upper()} changed from "
                        f"{register_change.before:#010x} to {register_change.after:#010x}."
                    ),
                )
            )
            if register_change.before != 0 and register_change.after == 0:
                why.append(
                    ExplanationEntry(
                        key="xor.zeroing",
                        label="XOR Zeroing",
                        text=(
                            f"XORing {register_change.register_name.upper()} with itself "
                            "clears the register to zero."
                        ),
                    )
                )
                shellcode_relevance.append(
                    ExplanationEntry(
                        key="xor_zeroing",
                        label="Register Clearing",
                        text=(
                            "Shellcode commonly uses XOR self-zeroing because it is compact "
                            "and avoids embedding zero-valued immediates."
                        ),
                    )
                )
            else:
                why.append(
                    ExplanationEntry(
                        key="xor.performed",
                        label="Bitwise XOR",
                        text="A bitwise XOR operation updated the destination register.",
                    )
                )

        interpretation.append(
            ExplanationEntry(
                key="register.numeric_value",
                label="Numeric Interpretation",
                text="The register result should be interpreted as the numeric output of XOR.",
            )
        )

        return self._assemble_explanation(
            trace,
            what_changed,
            why,
            interpretation,
            shellcode_relevance,
        )

    def _build_generic_explanation(self, trace: ExecutionTrace, state_diff: StateDiff) -> Explanation:
        return self._assemble_explanation(
            trace,
            [
                ExplanationEntry(
                    key="instruction.executed",
                    label="Instruction Executed",
                    text="The instruction executed and changed machine state.",
                )
            ],
            [
                ExplanationEntry(
                    key="context.limited",
                    label="Limited Context",
                    text="The trace did not include enough detail for a more specific explanation.",
                )
            ],
            [
                ExplanationEntry(
                    key="state.transition",
                    label="State Transition",
                    text="Review the recorded reads, writes, and register changes to inspect the transition.",
                )
            ],
            [
                ExplanationEntry(
                    key="memory_intuition",
                    label="Memory Intuition",
                    text="Understanding how state moves through memory remains the primary learning goal.",
                )
            ],
        )

    def _assemble_explanation(
        self,
        trace: ExecutionTrace,
        what_changed: list[ExplanationEntry],
        why: list[ExplanationEntry],
        interpretation: list[ExplanationEntry],
        shellcode_relevance: list[ExplanationEntry],
    ) -> Explanation:
        return Explanation(
            instruction=trace.instruction,
            changed_registers=trace.register_changes,
            memory_reads=trace.reads,
            memory_writes=trace.writes,
            stack_changes=trace.stack_changes,
            what_changed=what_changed or [
                ExplanationEntry(
                    key="state.updated",
                    label="State Updated",
                    text="The instruction updated machine state.",
                )
            ],
            why=why or [
                ExplanationEntry(
                    key="behavior.recorded",
                    label="Recorded Behavior",
                    text="The explanation reflects only the trace data that was available.",
                )
            ],
            interpretation=interpretation or [
                ExplanationEntry(
                    key="interpretation.pending",
                    label="Interpretation Pending",
                    text="Additional context is required for a richer interpretation.",
                )
            ],
            shellcode_relevance=shellcode_relevance or [
                ExplanationEntry(
                    key="relevance.general",
                    label="Shellcode Relevance",
                    text="State transitions matter because shellcode relies on precise register and memory control.",
                )
            ],
        )

    def _build_interpretation_entries(self, value: ByteSequence) -> list[ExplanationEntry]:
        entries: list[ExplanationEntry] = []
        if len(value) == 0:
            return entries
        ascii_text = value.to_ascii()
        entries.append(
            ExplanationEntry(
                key="bytes.hex_view",
                label="Hex View",
                text=f"The bytes are {value.to_hex()}.",
            )
        )
        if any(character != "." for character in ascii_text):
            entries.append(
                ExplanationEntry(
                    key="ascii.pointer_string",
                    label="ASCII Interpretation",
                    text=f'The bytes decode to the ASCII view "{ascii_text}".',
                )
            )
        if len(value) in {1, 2, 4, 8}:
            entries.append(
                ExplanationEntry(
                    key="integer.little_endian",
                    label="Little-Endian Integer",
                    text=(
                        f"Interpreted as little-endian, the value is "
                        f"{value.to_little_endian_int():#x}."
                    ),
                )
            )
        return entries
