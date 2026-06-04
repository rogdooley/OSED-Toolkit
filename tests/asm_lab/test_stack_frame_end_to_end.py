from pathlib import Path

import yaml

from asm_lab.cpu.executor import MinimalExecutor, run_fixture
from asm_lab.explanation import ExplanationEngine
from asm_lab.inspect import build_stack_frame_inspect_view
from asm_lab.models import GoldenLessonFixture
from asm_lab.validation import compare_fixture_output, compare_inspect_output


FIXTURE_PATH = Path("tests/asm_lab/fixtures/stack_frame_canonical.yaml")


def test_stack_frame_fixture_passes_end_to_end() -> None:
    fixture = GoldenLessonFixture.model_validate(yaml.safe_load(FIXTURE_PATH.read_text()))
    executor = MinimalExecutor()
    engine = ExplanationEngine()
    results = run_fixture(fixture, executor)

    for step, result in zip(fixture.steps, results, strict=True):
        assert step.expected_output is not None
        explanation = engine.build_explanation(result.execution_trace, result.state_diff)
        comparison = compare_fixture_output(
            execution_result=result,
            expected_output=step.expected_output,
            explanation=explanation,
            mode="strict",
        )
        assert comparison.passed, comparison.model_dump()

        if step.expected_output.inspect_views:
            register_map = {register.name.lower(): register.value for register in result.after_state.registers}
            actual_views = [
                build_stack_frame_inspect_view(
                    result.after_state,
                    register_map["ebp"],
                    register_map["esp"],
                    local_slot_count=2,
                    argument_slot_count=1,
                    return_address_symbolic_label="caller+0x25",
                )
            ]
            for actual_view, expected_view in zip(actual_views, step.expected_output.inspect_views, strict=True):
                inspect_result = compare_inspect_output(actual_view, expected_view)
                assert inspect_result.passed, inspect_result.model_dump()

    final_registers = {register.name.lower(): register.value for register in results[-1].after_state.registers}
    assert final_registers["ebp"] == 1244988
    assert final_registers["esp"] == 1244956
