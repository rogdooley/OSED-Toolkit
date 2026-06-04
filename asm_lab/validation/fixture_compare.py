"""Fixture comparison helpers for semantic and inspect outputs."""

from asm_lab.models import (
    ExecutionResult,
    Explanation,
    InspectSection,
    InspectViewModel,
    LessonStepAssertions,
    LessonStepExpectedOutput,
    StackRangeSection,
)
from .assertions import validate_step_assertions
from .results import AssertionFailure, AssertionValidationResult


def compare_fixture_output(
    execution_result: ExecutionResult,
    expected_output: LessonStepExpectedOutput,
    explanation: Explanation,
    mode: str = "strict",
) -> AssertionValidationResult:
    """Compare semantic executor output against a hand-authored fixture."""
    semantic_assertions = _build_semantic_assertions(expected_output)
    results = [
        _compare_before_state(execution_result, expected_output),
        _compare_after_state(execution_result, expected_output),
        _compare_execution_trace(execution_result, expected_output, mode),
        _compare_state_diff(execution_result, expected_output, mode),
        _compare_explanation_keys(explanation, expected_output),
        validate_step_assertions(
            semantic_assertions,
            execution_result.execution_trace,
            execution_result.state_diff,
            explanation,
        ),
    ]
    failures = [failure for result in results for failure in result.failures]
    checked_categories = [category for result in results for category in result.checked_categories]
    return AssertionValidationResult.from_failures(checked_categories, failures)


def compare_inspect_output(
    actual: InspectViewModel,
    expected: InspectViewModel,
) -> AssertionValidationResult:
    """Compare inspect rendering independently from semantic fixture output."""
    failures: list[AssertionFailure] = []
    checked_categories = ["inspect.subject", "inspect.raw_value", "inspect.sections"]

    if actual.subject != expected.subject:
        failures.append(
            AssertionFailure(
                category="inspect.subject",
                expected=expected.subject,
                actual=actual.subject,
                message="Inspect subject mismatch.",
            )
        )
    if actual.raw_value != expected.raw_value:
        failures.append(
            AssertionFailure(
                category="inspect.raw_value",
                expected=f"{expected.raw_value:#x}",
                actual=f"{actual.raw_value:#x}",
                message="Inspect raw value mismatch.",
            )
        )
    if len(actual.sections) != len(expected.sections):
        failures.append(
            AssertionFailure(
                category="inspect.sections",
                expected=str(len(expected.sections)),
                actual=str(len(actual.sections)),
                message="Inspect section count mismatch.",
            )
        )
        return AssertionValidationResult.from_failures(checked_categories, failures)

    for index, (actual_section, expected_section) in enumerate(
        zip(actual.sections, expected.sections, strict=True)
    ):
        if actual_section.label != expected_section.label:
            failures.append(
                AssertionFailure(
                    category="inspect.sections",
                    expected=f"{index}:{expected_section.label}",
                    actual=f"{index}:{actual_section.label}",
                    message="Inspect section label mismatch.",
                )
            )
        if type(actual_section) is not type(expected_section):
            failures.append(
                AssertionFailure(
                    category="inspect.sections",
                    expected=type(expected_section).__name__,
                    actual=type(actual_section).__name__,
                    message="Inspect section type mismatch.",
                )
            )
            continue
        if isinstance(actual_section, InspectSection) and isinstance(expected_section, InspectSection):
            _compare_flat_section(failures, index, actual_section, expected_section)
        elif isinstance(actual_section, StackRangeSection) and isinstance(expected_section, StackRangeSection):
            _compare_stack_range_section(failures, index, actual_section, expected_section)

    return AssertionValidationResult.from_failures(checked_categories, failures)


def _compare_flat_section(
    failures: list[AssertionFailure],
    index: int,
    actual_section: InspectSection,
    expected_section: InspectSection,
) -> None:
    if actual_section.format != expected_section.format:
        failures.append(
            AssertionFailure(
                category="inspect.sections",
                expected=f"{index}:{expected_section.format}",
                actual=f"{index}:{actual_section.format}",
                message="Inspect section format mismatch.",
            )
        )
    if actual_section.value != expected_section.value:
        failures.append(
            AssertionFailure(
                category="inspect.sections",
                expected=f"{index}:{expected_section.value}",
                actual=f"{index}:{actual_section.value}",
                message="Inspect section value mismatch.",
            )
        )
    if actual_section.raw_bytes != expected_section.raw_bytes:
        failures.append(
            AssertionFailure(
                category="inspect.sections",
                expected=(expected_section.raw_bytes.to_hex() if expected_section.raw_bytes is not None else "none"),
                actual=(actual_section.raw_bytes.to_hex() if actual_section.raw_bytes is not None else "none"),
                message="Inspect section raw-byte mismatch.",
            )
        )


def _compare_stack_range_section(
    failures: list[AssertionFailure],
    index: int,
    actual_section: StackRangeSection,
    expected_section: StackRangeSection,
) -> None:
    if actual_section.base_pointer_value != expected_section.base_pointer_value:
        failures.append(
            AssertionFailure(
                category="inspect.sections",
                expected=f"{index}:base={expected_section.base_pointer_value:#x}",
                actual=f"{index}:base={actual_section.base_pointer_value:#x}",
                message="Stack range base pointer mismatch.",
            )
        )
    if actual_section.stack_pointer_value != expected_section.stack_pointer_value:
        failures.append(
            AssertionFailure(
                category="inspect.sections",
                expected=f"{index}:stack={expected_section.stack_pointer_value:#x}",
                actual=f"{index}:stack={actual_section.stack_pointer_value:#x}",
                message="Stack range stack pointer mismatch.",
            )
        )
    if len(actual_section.entries) != len(expected_section.entries):
        failures.append(
            AssertionFailure(
                category="inspect.sections",
                expected=f"{index}:entries={len(expected_section.entries)}",
                actual=f"{index}:entries={len(actual_section.entries)}",
                message="Stack range entry count mismatch.",
            )
        )
        return
    for entry_index, (actual_entry, expected_entry) in enumerate(zip(actual_section.entries, expected_section.entries, strict=True)):
        if actual_entry != expected_entry:
            failures.append(
                AssertionFailure(
                    category="inspect.sections",
                    expected=f"{index}:{entry_index}:{expected_entry.model_dump_json()}",
                    actual=f"{index}:{entry_index}:{actual_entry.model_dump_json()}",
                    message="Stack range entry mismatch.",
                )
            )


def _compare_before_state(
    execution_result: ExecutionResult,
    expected_output: LessonStepExpectedOutput,
) -> AssertionValidationResult:
    expected_snapshot = expected_output.before_state
    checked_categories = ["before_state"]
    if expected_snapshot is None:
        return AssertionValidationResult.from_failures(checked_categories, [])
    if execution_result.before_state != expected_snapshot.machine_state:
        failure = AssertionFailure(
            category="before_state",
            expected=expected_snapshot.machine_state.model_dump_json(),
            actual=execution_result.before_state.model_dump_json(),
            message="Executor before-state does not match the expected snapshot.",
        )
        return AssertionValidationResult.from_failures(checked_categories, [failure])
    return AssertionValidationResult.from_failures(checked_categories, [])


def _compare_after_state(
    execution_result: ExecutionResult,
    expected_output: LessonStepExpectedOutput,
) -> AssertionValidationResult:
    expected_snapshot = expected_output.after_state or expected_output.state_snapshot
    checked_categories = ["after_state"]
    if expected_snapshot is None:
        return AssertionValidationResult.from_failures(checked_categories, [])
    if execution_result.after_state != expected_snapshot.machine_state:
        failure = AssertionFailure(
            category="after_state",
            expected=expected_snapshot.machine_state.model_dump_json(),
            actual=execution_result.after_state.model_dump_json(),
            message="Executor after-state does not match the expected snapshot.",
        )
        return AssertionValidationResult.from_failures(checked_categories, [failure])
    return AssertionValidationResult.from_failures(checked_categories, [])


def _compare_execution_trace(
    execution_result: ExecutionResult,
    expected_output: LessonStepExpectedOutput,
    mode: str,
) -> AssertionValidationResult:
    checked_categories = ["execution_trace"]
    if mode != "strict":
        return AssertionValidationResult.from_failures(checked_categories, [])
    if execution_result.execution_trace != expected_output.execution_trace:
        failure = AssertionFailure(
            category="execution_trace",
            expected=expected_output.execution_trace.model_dump_json(),
            actual=execution_result.execution_trace.model_dump_json(),
            message="Execution trace does not match the expected fixture output.",
        )
        return AssertionValidationResult.from_failures(checked_categories, [failure])
    return AssertionValidationResult.from_failures(checked_categories, [])


def _compare_state_diff(
    execution_result: ExecutionResult,
    expected_output: LessonStepExpectedOutput,
    mode: str,
) -> AssertionValidationResult:
    checked_categories = ["state_diff"]
    if mode != "strict":
        return AssertionValidationResult.from_failures(checked_categories, [])
    if execution_result.state_diff != expected_output.state_diff:
        failure = AssertionFailure(
            category="state_diff",
            expected=expected_output.state_diff.model_dump_json(),
            actual=execution_result.state_diff.model_dump_json(),
            message="State diff does not match the expected fixture output.",
        )
        return AssertionValidationResult.from_failures(checked_categories, [failure])
    return AssertionValidationResult.from_failures(checked_categories, [])


def _build_semantic_assertions(expected_output: LessonStepExpectedOutput) -> LessonStepAssertions:
    return LessonStepAssertions(
        explanation_categories=expected_output.explanation.categories,
        required_interpretation_keys=expected_output.explanation.interpretation_keys,
        required_shellcode_relevance_keys=expected_output.explanation.shellcode_relevance_keys,
    )


def _compare_explanation_keys(
    explanation: Explanation,
    expected_output: LessonStepExpectedOutput,
) -> AssertionValidationResult:
    failures: list[AssertionFailure] = []
    checked_categories = ["explanation.what_changed_keys", "explanation.why_keys"]
    actual_what_changed = {entry.key for entry in explanation.what_changed}
    actual_why = {entry.key for entry in explanation.why}

    for expected_key in expected_output.explanation.what_changed_keys:
        if expected_key not in actual_what_changed:
            failures.append(
                AssertionFailure(
                    category="explanation.what_changed_keys",
                    expected=expected_key,
                    actual=",".join(sorted(actual_what_changed)) or "none",
                    message=f"What-changed key {expected_key} was not emitted.",
                )
            )

    for expected_key in expected_output.explanation.why_keys:
        if expected_key not in actual_why:
            failures.append(
                AssertionFailure(
                    category="explanation.why_keys",
                    expected=expected_key,
                    actual=",".join(sorted(actual_why)) or "none",
                    message=f"Why key {expected_key} was not emitted.",
                )
            )

    return AssertionValidationResult.from_failures(checked_categories, failures)
