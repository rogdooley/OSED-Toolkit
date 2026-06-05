from pathlib import Path

import yaml

from asm_lab.cpu.executor import MinimalExecutor, run_fixture
from asm_lab.explanation import ExplanationEngine
from asm_lab.models import GoldenLessonFixture, InspectViewModel
from asm_lab.validation import compare_fixture_output, compare_inspect_output


FIXTURE_PATH = Path("tests/asm_lab/fixtures/pointer_lesson_calc_dword.yaml")


def _build_pointer_inspect_views(state, instruction: str) -> list[InspectViewModel]:
    register_map = {register.name.lower(): register.value for register in state.registers}
    region = state.memory_regions[0]
    region_bytes = region.bytes_value.data
    address = register_map["eax"]
    offset = address - region.start_address
    deref_bytes = region_bytes[offset : offset + 4]
    register_view = InspectViewModel.model_validate(
        {
            "title": "Register Inspection",
            "subject": "eax",
            "raw_value": address,
            "sections": [
                {"label": "Raw Value", "format": "hex", "value": "0x00002000"},
                {"label": "Interpretation", "format": "pointer", "value": "Address"},
                {"label": "Dereference Target", "format": "hex", "value": "0x00002000"},
            ],
            "common_meaning": (
                "EAX holds the address of the bytes that will be read."
                if instruction == "mov ebx, [eax]"
                else "EAX now holds a pointer to the memory location at 0x2000."
            ),
        }
    )
    if instruction == "mov eax, 0x2000":
        return [register_view]
    return [
        register_view,
        InspectViewModel.model_validate(
            {
                "title": "Dereference Inspection",
                "subject": "[eax]",
                "raw_value": address,
                "sections": [
                    {"label": "Address", "format": "hex", "value": "0x00002000"},
                    {
                        "label": "Bytes",
                        "format": "hex",
                        "value": "63 61 6c 63",
                        "raw_bytes": {"data": list(deref_bytes)},
                    },
                    {
                        "label": "ASCII",
                        "format": "ascii",
                        "value": "calc",
                        "raw_bytes": {"data": list(deref_bytes)},
                    },
                    {
                        "label": "DWORD",
                        "format": "unsigned",
                        "value": "0x636c6163",
                        "raw_bytes": {"data": list(deref_bytes)},
                    },
                ],
                "common_meaning": "Dereferencing EAX reads the DWORD stored at address 0x2000.",
            }
        ),
        InspectViewModel.model_validate(
            {
                "title": "Raw Memory Inspection",
                "subject": "0x2000",
                "raw_value": address,
                "sections": [
                    {
                        "label": "Bytes",
                        "format": "hex",
                        "value": "63 61 6c 63",
                        "raw_bytes": {"data": list(deref_bytes)},
                    },
                    {
                        "label": "ASCII",
                        "format": "ascii",
                        "value": "calc",
                        "raw_bytes": {"data": list(deref_bytes)},
                    },
                ],
                "common_meaning": "Raw memory at 0x2000 contains the four bytes that become EBX.",
            }
        ),
    ]


def test_pointer_lesson_passes_end_to_end() -> None:
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

        if step.expected_output.inspect_views:
            actual_views = _build_pointer_inspect_views(result.after_state, step.instruction)
            for actual_view, expected_view in zip(
                actual_views, step.expected_output.inspect_views, strict=True
            ):
                inspect_result = compare_inspect_output(actual_view, expected_view)
                assert inspect_result.passed, inspect_result.model_dump()

        current_state = result.after_state

    assert current_state.registers[0].value == 0x00002000
    assert current_state.registers[1].value == 0x636C6163
