from asm_lab.explanation import ExplanationEngine
from asm_lab.models import (
    ByteSequence,
    ExecutionTrace,
    Explanation,
    ExplanationCategory,
    ExplanationEntry,
    ExpectedMemoryRead,
    ExpectedRegisterChange,
    ExpectedStackPointerMovement,
    LessonStepAssertions,
    MemoryRead,
    MemoryWrite,
    RegisterChange,
    RegisterDiff,
    StackChange,
    StackDiff,
    StateDiff,
    Width,
)
from asm_lab.validation import validate_step_assertions


def test_successful_assertion_validation() -> None:
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
        register_changes=[
            RegisterChange(register_name="eax", before=0, after=0x636C6163, width_bits=32)
        ],
    )
    state_diff = StateDiff(
        register_diffs=[
            RegisterDiff(register_name="eax", before=0, after=0x636C6163, width_bits=32)
        ]
    )
    explanation = Explanation(
        instruction="mov eax, [esi]",
        what_changed=[
            ExplanationEntry(key="register.updated", label="Register Updated", text="x")
        ],
        why=[ExplanationEntry(key="pointer.followed", label="Pointer Dereference", text="x")],
        interpretation=[
            ExplanationEntry(key="ascii.pointer_string", label="ASCII Interpretation", text="x")
        ],
        shellcode_relevance=[
            ExplanationEntry(key="pointer_dereference", label="Pointer Dereference", text="x")
        ],
    )
    assertions = LessonStepAssertions(
        changed_registers=[ExpectedRegisterChange(register_name="eax", after=0x636C6163)],
        memory_reads=[
            ExpectedMemoryRead(
                address=0x2000,
                bytes_value=ByteSequence.model_validate([0x63, 0x61, 0x6C, 0x63]),
                width=Width.DWORD,
            )
        ],
        explanation_categories=[
            ExplanationCategory.WHAT_CHANGED,
            ExplanationCategory.INTERPRETATION,
            ExplanationCategory.SHELLCODE_RELEVANCE,
        ],
        required_interpretation_keys=["ascii.pointer_string"],
        required_shellcode_relevance_keys=["pointer_dereference"],
    )

    result = validate_step_assertions(assertions, trace, state_diff, explanation)

    assert result.passed is True
    assert result.failures == []


def test_failed_register_assertion() -> None:
    trace = ExecutionTrace(
        instruction="xor eax, eax",
        register_changes=[
            RegisterChange(register_name="eax", before=1, after=0, width_bits=32)
        ],
    )
    state_diff = StateDiff(
        register_diffs=[RegisterDiff(register_name="eax", before=1, after=0, width_bits=32)]
    )
    explanation = Explanation(
        instruction="xor eax, eax",
        what_changed=[ExplanationEntry(key="register.updated", label="Register Updated", text="x")],
        why=[ExplanationEntry(key="xor.zeroing", label="XOR Zeroing", text="x")],
        interpretation=[ExplanationEntry(key="register.numeric_value", label="Numeric", text="x")],
        shellcode_relevance=[ExplanationEntry(key="xor_zeroing", label="Register Clearing", text="x")],
    )
    assertions = LessonStepAssertions(
        changed_registers=[ExpectedRegisterChange(register_name="eax", after=2)]
    )

    result = validate_step_assertions(assertions, trace, state_diff, explanation)

    assert result.passed is False
    assert any(failure.category == "changed_registers" for failure in result.failures)


def test_failed_memory_assertion() -> None:
    trace = ExecutionTrace(
        instruction="mov eax, [esi]",
        reads=[MemoryRead(address=0x3000, bytes_value=[0x41], width=Width.BYTE, pointer_source="esi")],
    )
    state_diff = StateDiff()
    explanation = Explanation(
        instruction="mov eax, [esi]",
        what_changed=[ExplanationEntry(key="memory.read", label="Memory Read", text="x")],
        why=[ExplanationEntry(key="pointer.followed", label="Pointer Dereference", text="x")],
        interpretation=[ExplanationEntry(key="bytes.hex_view", label="Hex View", text="x")],
        shellcode_relevance=[ExplanationEntry(key="pointer_dereference", label="Pointer Dereference", text="x")],
    )
    assertions = LessonStepAssertions(
        memory_reads=[ExpectedMemoryRead(address=0x2000, width=Width.DWORD)]
    )

    result = validate_step_assertions(assertions, trace, state_diff, explanation)

    assert result.passed is False
    assert any(failure.category == "memory_reads" for failure in result.failures)


def test_failed_explanation_key_assertion() -> None:
    trace = ExecutionTrace(instruction="mov eax, [esi]")
    state_diff = StateDiff()
    explanation = Explanation(
        instruction="mov eax, [esi]",
        what_changed=[ExplanationEntry(key="register.updated", label="Register Updated", text="x")],
        why=[ExplanationEntry(key="pointer.followed", label="Pointer Dereference", text="x")],
        interpretation=[ExplanationEntry(key="bytes.hex_view", label="Hex View", text="x")],
        shellcode_relevance=[ExplanationEntry(key="pointer_dereference", label="Pointer Dereference", text="x")],
    )
    assertions = LessonStepAssertions(
        required_interpretation_keys=["ascii.pointer_string"]
    )

    result = validate_step_assertions(assertions, trace, state_diff, explanation)

    assert result.passed is False
    assert any(failure.category == "required_interpretation_keys" for failure in result.failures)


def test_stack_assertion_validation() -> None:
    trace = ExecutionTrace(
        instruction="push 0x636c6163",
        stack_changes=[
            StackChange(
                before=0x0012FF44,
                after=0x0012FF40,
                pushed_bytes=[0x63, 0x61, 0x6C, 0x63],
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
    )
    state_diff = StateDiff(
        stack_diffs=[
            StackDiff(
                before=0x0012FF44,
                after=0x0012FF40,
                pushed_bytes=[0x63, 0x61, 0x6C, 0x63],
            )
        ]
    )
    explanation = Explanation(
        instruction="push 0x636c6163",
        what_changed=[ExplanationEntry(key="stack.pointer_moved", label="Stack Pointer Moved", text="x")],
        why=[ExplanationEntry(key="push.grows_down", label="Stack Growth", text="x")],
        interpretation=[ExplanationEntry(key="ascii.pointer_string", label="ASCII", text="x")],
        shellcode_relevance=[ExplanationEntry(key="stack_string_construction", label="Stack String", text="x")],
    )
    assertions = LessonStepAssertions(
        stack_pointer_movement=ExpectedStackPointerMovement(
            register_name="esp",
            before=0x0012FF44,
            after=0x0012FF40,
            delta=-4,
        )
    )

    result = validate_step_assertions(assertions, trace, state_diff, explanation)

    assert result.passed is True
