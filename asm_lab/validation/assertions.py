"""Deterministic assertion matchers for ASM-Lab lesson validation."""

from asm_lab.models import (
    ExecutionTrace,
    Explanation,
    ExplanationCategory,
    LessonStepAssertions,
    StateDiff,
)
from .results import AssertionFailure, AssertionValidationResult


def validate_register_assertions(
    assertions: LessonStepAssertions,
    trace: ExecutionTrace,
    state_diff: StateDiff,
) -> AssertionValidationResult:
    failures: list[AssertionFailure] = []
    checked_categories = ["changed_registers"]
    actual_changes = {change.register_name: change for change in trace.register_changes}
    diff_changes = {change.register_name: change for change in state_diff.register_diffs}

    for expected in assertions.changed_registers:
        actual = actual_changes.get(expected.register_name)
        if actual is None:
            actual = diff_changes.get(expected.register_name)
        if actual is None:
            failures.append(
                AssertionFailure(
                    category="changed_registers",
                    expected=expected.register_name,
                    actual="missing",
                    message=f"Expected register change for {expected.register_name}.",
                )
            )
            continue
        if expected.before is not None and actual.before != expected.before:
            failures.append(
                AssertionFailure(
                    category="changed_registers",
                    expected=f"{expected.register_name}.before={expected.before:#x}",
                    actual=f"{actual.before:#x}",
                    message=f"Register {expected.register_name} before-value mismatch.",
                )
            )
        if expected.after is not None and actual.after != expected.after:
            failures.append(
                AssertionFailure(
                    category="changed_registers",
                    expected=f"{expected.register_name}.after={expected.after:#x}",
                    actual=f"{actual.after:#x}",
                    message=f"Register {expected.register_name} after-value mismatch.",
                )
            )

    return AssertionValidationResult.from_failures(checked_categories, failures)


def validate_memory_assertions(assertions: LessonStepAssertions, trace: ExecutionTrace) -> AssertionValidationResult:
    failures: list[AssertionFailure] = []
    checked_categories = ["memory_reads", "memory_writes"]

    for expected in assertions.memory_reads:
        matched = False
        for actual in trace.reads:
            if expected.address is not None and actual.address != expected.address:
                continue
            if expected.width is not None and actual.width != expected.width:
                continue
            if expected.pointer_source is not None and actual.pointer_source != expected.pointer_source:
                continue
            if expected.bytes_value is not None and actual.bytes_value != expected.bytes_value:
                continue
            matched = True
            break
        if not matched:
            failures.append(
                AssertionFailure(
                    category="memory_reads",
                    expected=_describe_expected_memory_read(expected),
                    actual=_describe_memory_reads(trace),
                    message="Expected memory read was not observed in the execution trace.",
                )
            )

    for expected in assertions.memory_writes:
        matched = False
        for actual in trace.writes:
            if expected.address is not None and actual.address != expected.address:
                continue
            if expected.width is not None and actual.width != expected.width:
                continue
            if expected.before_bytes is not None and actual.before_bytes != expected.before_bytes:
                continue
            if expected.after_bytes is not None and actual.after_bytes != expected.after_bytes:
                continue
            matched = True
            break
        if not matched:
            failures.append(
                AssertionFailure(
                    category="memory_writes",
                    expected=_describe_expected_memory_write(expected),
                    actual=_describe_memory_writes(trace),
                    message="Expected memory write was not observed in the execution trace.",
                )
            )

    return AssertionValidationResult.from_failures(checked_categories, failures)


def validate_stack_assertions(assertions: LessonStepAssertions, trace: ExecutionTrace) -> AssertionValidationResult:
    failures: list[AssertionFailure] = []
    checked_categories = ["stack_pointer_movement"]
    expected = assertions.stack_pointer_movement
    if expected is None:
        return AssertionValidationResult.from_failures(checked_categories, failures)

    actual = next(
        (
            change
            for change in trace.stack_changes
            if change.stack_pointer_register == expected.register_name
        ),
        None,
    )
    if actual is None:
        failures.append(
            AssertionFailure(
                category="stack_pointer_movement",
                expected=expected.register_name,
                actual="missing",
                message=f"Expected stack pointer movement for {expected.register_name}.",
            )
        )
        return AssertionValidationResult.from_failures(checked_categories, failures)

    if expected.before is not None and actual.before != expected.before:
        failures.append(
            AssertionFailure(
                category="stack_pointer_movement",
                expected=f"before={expected.before:#x}",
                actual=f"{actual.before:#x}",
                message="Stack pointer before-value mismatch.",
            )
        )
    if expected.after is not None and actual.after != expected.after:
        failures.append(
            AssertionFailure(
                category="stack_pointer_movement",
                expected=f"after={expected.after:#x}",
                actual=f"{actual.after:#x}",
                message="Stack pointer after-value mismatch.",
            )
        )
    if actual.delta != expected.delta:
        failures.append(
            AssertionFailure(
                category="stack_pointer_movement",
                expected=f"delta={expected.delta}",
                actual=f"delta={actual.delta}",
                message="Stack pointer delta mismatch.",
            )
        )

    return AssertionValidationResult.from_failures(checked_categories, failures)


def validate_explanation_assertions(
    assertions: LessonStepAssertions, explanation: Explanation
) -> AssertionValidationResult:
    failures: list[AssertionFailure] = []
    checked_categories = [
        "explanation_categories",
        "required_interpretation_keys",
        "required_shellcode_relevance_keys",
    ]

    emitted_categories = explanation.emitted_categories()
    for expected in assertions.explanation_categories:
        if expected not in emitted_categories:
            failures.append(
                AssertionFailure(
                    category="explanation_categories",
                    expected=expected.value,
                    actual=",".join(sorted(category.value for category in emitted_categories)) or "none",
                    message=f"Explanation category {expected.value} was not emitted.",
                )
            )

    interpretation_keys = {entry.key for entry in explanation.interpretation}
    for expected_key in assertions.required_interpretation_keys:
        if expected_key not in interpretation_keys:
            failures.append(
                AssertionFailure(
                    category="required_interpretation_keys",
                    expected=expected_key,
                    actual=",".join(sorted(interpretation_keys)) or "none",
                    message=f"Interpretation key {expected_key} was not emitted.",
                )
            )

    shellcode_keys = {entry.key for entry in explanation.shellcode_relevance}
    for expected_key in assertions.required_shellcode_relevance_keys:
        if expected_key not in shellcode_keys:
            failures.append(
                AssertionFailure(
                    category="required_shellcode_relevance_keys",
                    expected=expected_key,
                    actual=",".join(sorted(shellcode_keys)) or "none",
                    message=f"Shellcode relevance key {expected_key} was not emitted.",
                )
            )

    return AssertionValidationResult.from_failures(checked_categories, failures)


def validate_step_assertions(
    assertions: LessonStepAssertions,
    trace: ExecutionTrace,
    state_diff: StateDiff,
    explanation: Explanation,
) -> AssertionValidationResult:
    results = [
        validate_register_assertions(assertions, trace, state_diff),
        validate_memory_assertions(assertions, trace),
        validate_stack_assertions(assertions, trace),
        validate_explanation_assertions(assertions, explanation),
    ]
    failures = [failure for result in results for failure in result.failures]
    checked_categories = [category for result in results for category in result.checked_categories]
    return AssertionValidationResult.from_failures(checked_categories, failures)


def _describe_expected_memory_read(expected: object) -> str:
    return str(expected)


def _describe_expected_memory_write(expected: object) -> str:
    return str(expected)


def _describe_memory_reads(trace: ExecutionTrace) -> str:
    if not trace.reads:
        return "none"
    return "; ".join(
        f"{read.address:#x}:{read.bytes_value.to_hex()}" for read in trace.reads
    )


def _describe_memory_writes(trace: ExecutionTrace) -> str:
    if not trace.writes:
        return "none"
    return "; ".join(
        f"{write.address:#x}:{write.after_bytes.to_hex()}" for write in trace.writes
    )
