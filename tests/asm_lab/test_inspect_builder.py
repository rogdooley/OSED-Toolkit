from asm_lab.inspect import build_stack_frame_inspect_view
from asm_lab.models import ByteSequence, MachineState, MemoryRegion, RegisterState, StackRangeSection, StackRole


def _build_state(*, ebp: int, esp: int, memory_start: int, memory_bytes: list[int]) -> MachineState:
    return MachineState(
        registers=[
            RegisterState(name="ebp", width_bits=32, value=ebp),
            RegisterState(name="esp", width_bits=32, value=esp),
            RegisterState(name="eip", width_bits=32, value=0x00403000),
        ],
        memory_regions=[
            MemoryRegion(
                start_address=memory_start,
                bytes_value=ByteSequence(data=bytes(memory_bytes)),
                label="stack-frame-window",
            )
        ],
    )


def test_build_stack_frame_inspect_view_matches_canonical_frame_layout() -> None:
    state = _build_state(
        ebp=0x0012FF3C,
        esp=0x0012FF1C,
        memory_start=0x0012FF34,
        memory_bytes=[
            0x41, 0x41, 0x41, 0x41,
            0x42, 0x42, 0x42, 0x42,
            0x50, 0xFF, 0x12, 0x00,
            0x00, 0x10, 0x40, 0x00,
            0x63, 0x61, 0x6C, 0x63,
        ],
    )

    view = build_stack_frame_inspect_view(
        state,
        0x0012FF3C,
        0x0012FF1C,
        local_slot_count=2,
        argument_slot_count=1,
        return_address_symbolic_label="main+0x25",
    )

    section = view.sections[0]
    assert isinstance(section, StackRangeSection)
    assert [entry.role for entry in section.entries] == [
        StackRole.LOCAL,
        StackRole.LOCAL,
        StackRole.SAVED_EBP,
        StackRole.RETURN_ADDRESS,
        StackRole.ARGUMENT,
    ]
    assert [entry.label for entry in section.entries if entry.role is StackRole.LOCAL] == [
        "local_2",
        "local_1",
    ]
    assert section.entries[3].symbolic_value == "main+0x25"
    assert section.entries[4].label == "argument_1"


def test_build_stack_frame_inspect_view_supports_multiple_arguments() -> None:
    state = _build_state(
        ebp=0x0012FF40,
        esp=0x0012FF20,
        memory_start=0x0012FF38,
        memory_bytes=[
            0x11, 0x11, 0x11, 0x11,
            0x22, 0x22, 0x22, 0x22,
            0x50, 0xFF, 0x12, 0x00,
            0x25, 0x10, 0x40, 0x00,
            0x41, 0x41, 0x41, 0x41,
            0x42, 0x42, 0x42, 0x42,
            0x43, 0x43, 0x43, 0x43,
        ],
    )

    view = build_stack_frame_inspect_view(
        state,
        0x0012FF40,
        0x0012FF20,
        local_byte_size=8,
        argument_slot_count=3,
        return_address_symbolic_label="caller+0x25",
    )

    section = view.sections[0]
    assert isinstance(section, StackRangeSection)
    argument_entries = [entry for entry in section.entries if entry.role is StackRole.ARGUMENT]
    assert [entry.address for entry in argument_entries] == [0x0012FF48, 0x0012FF4C, 0x0012FF50]
    assert [entry.label for entry in argument_entries] == ["argument_1", "argument_2", "argument_3"]
    assert [entry.symbolic_value for entry in argument_entries] == ["argument_1", "argument_2", "argument_3"]
