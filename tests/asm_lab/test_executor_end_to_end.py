from pathlib import Path

import yaml

from asm_lab.cpu.executor import MinimalExecutor, run_fixture
from asm_lab.explanation import ExplanationEngine
from asm_lab.models import GoldenLessonFixture
from asm_lab.validation import compare_fixture_output


FIXTURE_PATH = Path("tests/asm_lab/fixtures/stack_strings_calc_exe.yaml")


def test_minimal_executor_reproduces_stack_strings_fixture() -> None:
    fixture = GoldenLessonFixture.model_validate(yaml.safe_load(FIXTURE_PATH.read_text()))
    executor = MinimalExecutor()
    engine = ExplanationEngine()

    results = run_fixture(fixture, executor)

    current_state = fixture.initial_state
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
        current_state = result.after_state

    assert current_state.registers[1].value == fixture.final_stack_pointer
    assert current_state.memory_regions[0].bytes_value == fixture.final_memory_at_stack_pointer


def test_run_fixture_returns_step_ordered_execution_results() -> None:
    fixture = GoldenLessonFixture.model_validate(yaml.safe_load(FIXTURE_PATH.read_text()))
    results = run_fixture(fixture, MinimalExecutor())

    assert len(results) == len(fixture.steps)
    assert results[0].execution_trace.instruction == "xor eax, eax"
    assert results[-1].execution_trace.instruction == "push 0x636c6163"
