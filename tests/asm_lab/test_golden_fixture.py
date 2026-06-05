from pathlib import Path

import yaml

from asm_lab.models import GoldenLessonFixture


FIXTURE_PATH = Path("tests/asm_lab/fixtures/stack_strings_calc_exe.yaml")


def test_stack_strings_calc_exe_fixture_validates_against_models() -> None:
    payload = yaml.safe_load(FIXTURE_PATH.read_text())
    fixture = GoldenLessonFixture.model_validate(payload)

    assert fixture.metadata.title == "Stack Strings - calc.exe"
    assert len(fixture.steps) == 4
    assert fixture.final_memory_at_stack_pointer.to_ascii() == "calc.exe...."


def test_stack_strings_calc_exe_fixture_contains_expected_encodings() -> None:
    payload = yaml.safe_load(FIXTURE_PATH.read_text())
    fixture = GoldenLessonFixture.model_validate(payload)

    encodings = [
        step.expected_output.instruction_encoding.bytes_value.to_hex()
        for step in fixture.steps
        if step.expected_output and step.expected_output.instruction_encoding
    ]

    assert encodings == [
        "31 c0",
        "50",
        "68 2e 65 78 65",
        "68 63 61 6c 63",
    ]


def test_stack_strings_calc_exe_fixture_final_stack_bytes_represent_calc_exe() -> None:
    payload = yaml.safe_load(FIXTURE_PATH.read_text())
    fixture = GoldenLessonFixture.model_validate(payload)

    final_bytes = fixture.final_memory_at_stack_pointer.data

    assert final_bytes[:9] == b"calc.exe\x00"
    assert fixture.final_stack_pointer == 0x0012FF38


def test_stack_strings_calc_exe_fixture_exposes_expected_inspect_view() -> None:
    payload = yaml.safe_load(FIXTURE_PATH.read_text())
    fixture = GoldenLessonFixture.model_validate(payload)

    final_step = fixture.steps[-1]
    assert final_step.expected_output is not None
    inspect_view = final_step.expected_output.inspect_views[0]

    assert inspect_view.subject == "esp"
    assert inspect_view.raw_value == 0x0012FF38
    assert inspect_view.sections[1].raw_bytes is not None
    assert inspect_view.sections[1].raw_bytes.to_hex() == "63 61 6c 63 2e 65 78 65 00 00 00 00"
