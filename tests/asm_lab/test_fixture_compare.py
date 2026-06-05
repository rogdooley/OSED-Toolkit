from asm_lab.models import (
    ExecutionResult,
    ExecutionTrace,
    Explanation,
    ExplanationCategory,
    ExplanationEntry,
    InspectSection,
    InspectViewModel,
    LessonStepExpectedOutput,
    MachineState,
    RegisterChange,
    RegisterState,
    StateDiff,
    StateSnapshot,
    ValueFormat,
)
from asm_lab.validation import compare_fixture_output, compare_inspect_output


def test_compare_fixture_output_passes_with_matching_states_and_semantics() -> None:
    before_state = MachineState(
        registers=[RegisterState(name="eax", width_bits=32, value=0x41414141)]
    )
    after_state = MachineState(
        registers=[RegisterState(name="eax", width_bits=32, value=0)]
    )
    execution_result = ExecutionResult(
        before_state=before_state,
        after_state=after_state,
        execution_trace=ExecutionTrace(
            instruction="xor eax, eax",
            register_changes=[
                RegisterChange(
                    register_name="eax",
                    before=0x41414141,
                    after=0,
                    width_bits=32,
                )
            ],
        ),
        state_diff=StateDiff(),
    )
    expected_output = LessonStepExpectedOutput(
        execution_trace=ExecutionTrace(
            instruction="xor eax, eax",
            register_changes=[
                RegisterChange(
                    register_name="eax",
                    before=0x41414141,
                    after=0,
                    width_bits=32,
                )
            ],
        ),
        state_diff=StateDiff(),
        explanation={
            "categories": [
                ExplanationCategory.WHAT_CHANGED,
                ExplanationCategory.WHY,
                ExplanationCategory.INTERPRETATION,
                ExplanationCategory.SHELLCODE_RELEVANCE,
            ],
            "what_changed_keys": ["register.updated"],
            "why_keys": ["xor.zeroing"],
            "interpretation_keys": ["register.numeric_value"],
            "shellcode_relevance_keys": ["xor_zeroing"],
        },
        before_state=StateSnapshot(label="before", machine_state=before_state),
        after_state=StateSnapshot(label="after", machine_state=after_state),
    )
    explanation = Explanation(
        instruction="xor eax, eax",
        what_changed=[ExplanationEntry(key="register.updated", label="Register Updated", text="x")],
        why=[ExplanationEntry(key="xor.zeroing", label="XOR Zeroing", text="x")],
        interpretation=[
            ExplanationEntry(key="register.numeric_value", label="Numeric", text="x")
        ],
        shellcode_relevance=[
            ExplanationEntry(key="xor_zeroing", label="Register Clearing", text="x")
        ],
    )
    result = compare_fixture_output(execution_result, expected_output, explanation, mode="strict")

    assert result.passed is True
    assert result.failures == []


def test_compare_inspect_output_reports_separate_failures() -> None:
    expected = InspectViewModel(
        title="ESP Inspection",
        subject="esp",
        raw_value=0x0012FF38,
        sections=[
            InspectSection(label="ASCII", format=ValueFormat.ASCII, value="calc"),
        ],
    )
    actual = InspectViewModel(
        title="ESP Inspection",
        subject="esp",
        raw_value=0x0012FF39,
        sections=[
            InspectSection(label="ASCII", format=ValueFormat.ASCII, value="calc.exe"),
        ],
    )

    result = compare_inspect_output(actual, expected)

    assert result.passed is False
    assert any(failure.category == "inspect.raw_value" for failure in result.failures)
