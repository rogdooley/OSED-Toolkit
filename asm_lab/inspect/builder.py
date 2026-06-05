"""Shared inspect builders for lesson-driven memory views."""

from __future__ import annotations

from asm_lab.models import (
    ByteSequence,
    InspectViewModel,
    MachineState,
    StackRangeEntry,
    StackRangeSection,
    StackRole,
)


def build_stack_frame_inspect_view(
    state: MachineState,
    ebp_value: int,
    esp_value: int,
    *,
    local_slot_count: int | None = None,
    local_byte_size: int | None = None,
    argument_slot_count: int = 1,
    return_address_symbolic_label: str | None = None,
) -> InspectViewModel:
    """Build a role-aware inspect view for a canonical x86 stack frame."""
    normalized_local_slots = _normalize_local_slots(local_slot_count, local_byte_size)
    memory = _memory_map(state)
    entries: list[StackRangeEntry] = []

    for slot_index in range(normalized_local_slots, 0, -1):
        address = ebp_value - (slot_index * 4)
        label = f"local_{slot_index}"
        entries.append(
            StackRangeEntry(
                address=address,
                offset_from_ebp=address - ebp_value,
                raw_bytes=_read_dword(memory, address),
                numeric_value=_read_numeric_value(memory, address),
                symbolic_value=label,
                role=StackRole.LOCAL,
                label=label,
            )
        )

    entries.append(
        StackRangeEntry(
            address=ebp_value,
            offset_from_ebp=0,
            raw_bytes=_read_dword(memory, ebp_value),
            numeric_value=_read_numeric_value(memory, ebp_value),
            symbolic_value="saved caller frame",
            role=StackRole.SAVED_EBP,
        )
    )

    return_address = ebp_value + 4
    entries.append(
        StackRangeEntry(
            address=return_address,
            offset_from_ebp=4,
            raw_bytes=_read_dword(memory, return_address),
            numeric_value=_read_numeric_value(memory, return_address),
            symbolic_value=return_address_symbolic_label or "return_address",
            role=StackRole.RETURN_ADDRESS,
        )
    )

    for slot_index in range(1, argument_slot_count + 1):
        address = ebp_value + 4 + (slot_index * 4)
        label = f"argument_{slot_index}"
        entries.append(
            StackRangeEntry(
                address=address,
                offset_from_ebp=address - ebp_value,
                raw_bytes=_read_dword(memory, address),
                numeric_value=_read_numeric_value(memory, address),
                symbolic_value=label,
                role=StackRole.ARGUMENT,
                label=label,
            )
        )

    return InspectViewModel(
        title="Stack Frame Inspection",
        subject="stack-frame",
        raw_value=ebp_value,
        sections=[
            StackRangeSection(
                label="Stack Range",
                base_pointer_value=ebp_value,
                stack_pointer_value=esp_value,
                entries=entries,
            )
        ],
        common_meaning="The stack frame now has locals below EBP and caller data above EBP.",
    )


def _normalize_local_slots(local_slot_count: int | None, local_byte_size: int | None) -> int:
    if local_slot_count is not None and local_byte_size is not None:
        msg = "Provide local_slot_count or local_byte_size, not both."
        raise ValueError(msg)
    if local_slot_count is not None:
        if local_slot_count < 0:
            msg = "local_slot_count must be non-negative."
            raise ValueError(msg)
        return local_slot_count
    if local_byte_size is not None:
        if local_byte_size < 0 or local_byte_size % 4 != 0:
            msg = "local_byte_size must be a non-negative multiple of 4."
            raise ValueError(msg)
        return local_byte_size // 4
    msg = "A stack-frame inspect view requires local_slot_count or local_byte_size."
    raise ValueError(msg)


def _memory_map(state: MachineState) -> dict[int, int]:
    memory: dict[int, int] = {}
    for region in state.memory_regions:
        for offset, byte_value in enumerate(region.bytes_value.data):
            memory[region.start_address + offset] = byte_value
    return memory


def _read_dword(memory: dict[int, int], address: int) -> ByteSequence:
    return ByteSequence(data=bytes(memory.get(address + offset, 0) for offset in range(4)))


def _read_numeric_value(memory: dict[int, int], address: int) -> int:
    return _read_dword(memory, address).to_little_endian_int()
