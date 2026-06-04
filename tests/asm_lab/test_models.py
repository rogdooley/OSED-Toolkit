from pydantic import ValidationError

from asm_lab.models import (
    ByteSequence,
    ExecutionTrace,
    ExplanationCategory,
    GoldenLessonFixture,
    InspectViewModel,
    StackRangeEntry,
    StackRangeSection,
    StackRole,
    ExpectedMemoryWrite,
    ExpectedRegisterChange,
    ExpectedMemoryRead,
    ExpectedStackPointerMovement,
    InstructionEncoding,
    LessonStep,
    LessonStepExpectedOutput,
    LessonStepAssertions,
    MemoryDiff,
    MemoryRead,
    MemoryWrite,
    PredictionPrompt,
    RegisterChange,
    RegisterDiff,
    StateSnapshot,
    StackChange,
    StackDiff,
    StateDiff,
    Width,
)


def test_byte_sequence_normalizes_from_bytes() -> None:
    value = ByteSequence.model_validate(b"\x63\x61\x6c\x63")
    assert value.data == b"\x63\x61\x6c\x63"


def test_byte_sequence_normalizes_from_bytearray() -> None:
    value = ByteSequence.model_validate(bytearray(b"\x41\x42"))
    assert value.data == b"\x41\x42"


def test_byte_sequence_normalizes_from_int_list() -> None:
    value = ByteSequence.model_validate([0x41, 0x42, 0x43])
    assert value.data == b"ABC"


def test_byte_sequence_rejects_out_of_range_values() -> None:
    try:
        ByteSequence.model_validate([0x41, 0x100])
    except ValidationError as error:
        assert "0x00-0xff" in str(error)
    else:
        raise AssertionError("Expected byte validation failure.")


def test_byte_sequence_hex_rendering() -> None:
    value = ByteSequence.model_validate([0x63, 0x61, 0x6C, 0x63])
    assert value.to_hex() == "63 61 6c 63"


def test_byte_sequence_ascii_rendering_uses_safe_replacement() -> None:
    value = ByteSequence.model_validate([0x41, 0x00, 0x7F, 0x42])
    assert value.to_ascii() == "A..B"


def test_byte_sequence_little_endian_interpretation() -> None:
    value = ByteSequence.model_validate([0x78, 0x56, 0x34, 0x12])
    assert value.to_little_endian_int() == 0x12345678


def test_expected_register_change_requires_before_or_after() -> None:
    try:
        ExpectedRegisterChange(register_name="eax")
    except ValidationError as error:
        assert "before or after" in str(error)
    else:
        raise AssertionError("Expected register assertion validation failure.")


def test_expected_memory_write_requires_address_or_bytes() -> None:
    try:
        ExpectedMemoryWrite()
    except ValidationError as error:
        assert "address or byte transition" in str(error)
    else:
        raise AssertionError("Expected memory-write assertion validation failure.")


def test_expected_memory_read_requires_address_bytes_or_width() -> None:
    try:
        ExpectedMemoryRead()
    except ValidationError as error:
        assert "address, bytes, or width" in str(error)
    else:
        raise AssertionError("Expected memory-read assertion validation failure.")


def test_lesson_step_assertions_accept_category_keys() -> None:
    step = LessonStep(
        instruction="mov eax, [esi]",
        assertions=LessonStepAssertions(
            changed_registers=[ExpectedRegisterChange(register_name="eax", after=0x636C6163)],
            explanation_categories=[
                ExplanationCategory.WHAT_CHANGED,
                ExplanationCategory.INTERPRETATION,
            ],
            required_interpretation_keys=["ascii.pointer_string"],
            required_shellcode_relevance_keys=["pointer_dereference"],
        ),
    )
    assert step.assertions is not None
    assert step.assertions.required_interpretation_keys == ["ascii.pointer_string"]


def test_stack_pointer_assertion_accepts_before_after_and_delta() -> None:
    assertion = ExpectedStackPointerMovement(
        register_name="esp",
        before=0x0012FF44,
        after=0x0012FF40,
        delta=-4,
    )
    assert assertion.delta == -4


def test_instruction_encoding_normalizes_bytes() -> None:
    encoding = InstructionEncoding(bytes_value=[0x31, 0xC0])
    assert encoding.bytes_value.to_hex() == "31 c0"


def test_lesson_step_supports_prediction_prompt_and_expected_output() -> None:
    step = LessonStep(
        instruction="xor eax, eax",
        prediction_prompt=PredictionPrompt(prompt="What happens to EAX?", focus=["register state"]),
        expected_output=LessonStepExpectedOutput(
            execution_trace=ExecutionTrace(instruction="xor eax, eax"),
            state_diff=StateDiff(),
            explanation={
                "categories": [ExplanationCategory.WHAT_CHANGED],
                "what_changed_keys": ["register.updated"],
            },
            state_snapshot=StateSnapshot(
                label="after-xor",
                machine_state={
                    "architecture": "x86",
                    "registers": [],
                    "memory_regions": [],
                },
            ),
        ),
    )
    assert step.prediction_prompt is not None
    assert step.expected_output is not None
    assert step.expected_output.explanation.what_changed_keys == ["register.updated"]


def test_state_diff_serializes_canonical_byte_sequences() -> None:
    diff = StateDiff(
        register_diffs=[RegisterDiff(register_name="eax", before=0, after=1, width_bits=32)],
        memory_diffs=[
            MemoryDiff(
                address=0x2000,
                before_bytes=[0x00, 0x00, 0x00, 0x00],
                after_bytes=[0x63, 0x61, 0x6C, 0x63],
                width=Width.DWORD,
            )
        ],
        stack_diffs=[
            StackDiff(
                before=0x0012FF44,
                after=0x0012FF40,
                pushed_bytes=[0x63, 0x61, 0x6C, 0x63],
            )
        ],
    )
    payload = diff.model_dump()
    assert payload["memory_diffs"][0]["after_bytes"]["data"] == [0x63, 0x61, 0x6C, 0x63]
    assert payload["stack_diffs"][0]["pushed_bytes"]["data"] == [0x63, 0x61, 0x6C, 0x63]


def test_execution_trace_serializes_reads_writes_and_changes() -> None:
    trace = ExecutionTrace(
        instruction="mov eax, [esi]",
        operands=["eax", "[esi]"],
        reads=[
            MemoryRead(
                address=0x2000,
                bytes_value=[0x63, 0x61, 0x6C, 0x63],
                width=Width.DWORD,
                pointer_source="esi",
            )
        ],
        writes=[
            MemoryWrite(
                address=0x0012FF40,
                before_bytes=[0x00, 0x00, 0x00, 0x00],
                after_bytes=[0x63, 0x61, 0x6C, 0x63],
                width=Width.DWORD,
            )
        ],
        register_changes=[
            RegisterChange(register_name="eax", before=0, after=0x636C6163, width_bits=32)
        ],
        stack_changes=[
            StackChange(
                before=0x0012FF44,
                after=0x0012FF40,
                pushed_bytes=[0x63, 0x61, 0x6C, 0x63],
            )
        ],
    )
    payload = trace.model_dump()
    assert payload["reads"][0]["bytes_value"]["data"] == [0x63, 0x61, 0x6C, 0x63]
    assert payload["writes"][0]["after_bytes"]["data"] == [0x63, 0x61, 0x6C, 0x63]
    assert payload["register_changes"][0]["after"] == 0x636C6163


def test_inspect_view_model_can_represent_canonical_stack_frame() -> None:
    frame_view = InspectViewModel(
        title="Stack Frame Inspection",
        subject="stack-frame",
        raw_value=0x0012FF3C,
        sections=[
            StackRangeSection(
                label="Stack Range",
                base_pointer_value=0x0012FF3C,
                stack_pointer_value=0x0012FF1C,
                entries=[
                    StackRangeEntry(
                        address=0x0012FF34,
                        offset_from_ebp=-8,
                        raw_bytes=[0x41, 0x41, 0x41, 0x41],
                        numeric_value=0x41414141,
                        symbolic_value=None,
                        role=StackRole.LOCAL,
                        label="local_2",
                    ),
                    StackRangeEntry(
                        address=0x0012FF38,
                        offset_from_ebp=-4,
                        raw_bytes=[0x42, 0x42, 0x42, 0x42],
                        numeric_value=0x42424242,
                        symbolic_value=None,
                        role=StackRole.LOCAL,
                        label="local_1",
                    ),
                    StackRangeEntry(
                        address=0x0012FF3C,
                        offset_from_ebp=0,
                        raw_bytes=[0x50, 0xFF, 0x12, 0x00],
                        numeric_value=0x0012FF50,
                        symbolic_value="saved caller frame",
                        role=StackRole.SAVED_EBP,
                    ),
                    StackRangeEntry(
                        address=0x0012FF40,
                        offset_from_ebp=4,
                        raw_bytes=[0x00, 0x10, 0x40, 0x00],
                        numeric_value=0x00401000,
                        symbolic_value="main+0x25",
                        role=StackRole.RETURN_ADDRESS,
                    ),
                    StackRangeEntry(
                        address=0x0012FF44,
                        offset_from_ebp=8,
                        raw_bytes=[0x63, 0x61, 0x6C, 0x63],
                        numeric_value=0x636C6163,
                        symbolic_value="argument_1",
                        role=StackRole.ARGUMENT,
                    ),
                ],
            )
        ],
    )

    stack_section = frame_view.sections[0]
    assert isinstance(stack_section, StackRangeSection)
    assert stack_section.entries[2].role is StackRole.SAVED_EBP
    assert stack_section.entries[3].role is StackRole.RETURN_ADDRESS
    assert stack_section.entries[4].symbolic_value == "argument_1"
