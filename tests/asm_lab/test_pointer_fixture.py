from pathlib import Path

import yaml

from asm_lab.models import GoldenLessonFixture


FIXTURE_PATH = Path("tests/asm_lab/fixtures/pointer_lesson_calc_dword.yaml")


def test_pointer_lesson_fixture_validates_against_models() -> None:
    fixture = GoldenLessonFixture.model_validate(yaml.safe_load(FIXTURE_PATH.read_text()))

    assert fixture.metadata.title == "Pointer Lesson - calc DWORD"
    assert len(fixture.steps) == 2
    assert fixture.steps[1].expected_output is not None


def test_pointer_lesson_fixture_uses_eax_and_ebx_roles() -> None:
    fixture = GoldenLessonFixture.model_validate(yaml.safe_load(FIXTURE_PATH.read_text()))

    first_step = fixture.steps[0].expected_output
    second_step = fixture.steps[1].expected_output
    assert first_step is not None
    assert second_step is not None

    assert first_step.execution_trace.register_changes[0].register_name == "eax"
    assert second_step.execution_trace.register_changes[0].register_name == "ebx"
    assert second_step.execution_trace.reads[0].pointer_source == "eax"


def test_pointer_lesson_fixture_requires_three_inspect_perspectives() -> None:
    fixture = GoldenLessonFixture.model_validate(yaml.safe_load(FIXTURE_PATH.read_text()))

    inspect_views = fixture.steps[1].expected_output.inspect_views

    assert [view.subject for view in inspect_views] == ["eax", "[eax]", "0x2000"]
    assert inspect_views[0].sections[2].label == "Dereference Target"
    assert inspect_views[0].sections[2].value == "0x00002000"
    assert inspect_views[1].sections[1].raw_bytes is not None
    assert inspect_views[1].sections[1].raw_bytes.to_hex() == "63 61 6c 63"
    assert inspect_views[1].sections[2].value == "calc"


def test_pointer_lesson_fixture_expected_result_is_calc_dword() -> None:
    fixture = GoldenLessonFixture.model_validate(yaml.safe_load(FIXTURE_PATH.read_text()))

    second_step = fixture.steps[1].expected_output
    assert second_step is not None
    assert second_step.execution_trace.register_changes[0].after == 0x636C6163


def test_pointer_lesson_fixture_requires_pointer_contract_keys() -> None:
    fixture = GoldenLessonFixture.model_validate(yaml.safe_load(FIXTURE_PATH.read_text()))

    first_step = fixture.steps[0].expected_output
    second_step = fixture.steps[1].expected_output
    assert first_step is not None
    assert second_step is not None

    assert set(first_step.explanation.why_keys) == {"pointer_setup", "address_vs_value"}
    assert set(first_step.explanation.interpretation_keys) == {
        "address_vs_value",
        "pointer_setup",
    }
    assert set(second_step.explanation.what_changed_keys) == {
        "memory_read",
        "register_updated_from_memory",
    }
    assert set(second_step.explanation.why_keys) == {"pointer_dereference"}
    assert set(second_step.explanation.interpretation_keys) == {
        "address_vs_value",
        "little_endian_interpretation",
    }
