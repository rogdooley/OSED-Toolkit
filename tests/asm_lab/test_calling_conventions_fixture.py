from pathlib import Path

import yaml

from asm_lab.models import GoldenLessonFixture, StackRangeSection, StackRole


FIXTURE_PATH = Path("tests/asm_lab/fixtures/calling_conventions_cdecl_arguments.yaml")


def test_calling_conventions_fixture_validates_against_models() -> None:
    fixture = GoldenLessonFixture.model_validate(yaml.safe_load(FIXTURE_PATH.read_text()))

    assert fixture.metadata.title == "Calling Conventions - cdecl Arguments"
    assert len(fixture.steps) == 3


def test_calling_conventions_fixture_uses_cdecl_argument_access_sequence() -> None:
    fixture = GoldenLessonFixture.model_validate(yaml.safe_load(FIXTURE_PATH.read_text()))

    assert [step.instruction for step in fixture.steps] == [
        "mov eax, [ebp+8]",
        "mov ebx, [ebp+12]",
        "mov ecx, [ebp+16]",
    ]


def test_calling_conventions_fixture_requires_argument_contract_keys() -> None:
    fixture = GoldenLessonFixture.model_validate(yaml.safe_load(FIXTURE_PATH.read_text()))

    for step in fixture.steps:
        expected_output = step.expected_output
        assert expected_output is not None
        assert set(expected_output.explanation.what_changed_keys) == {
            "register_updated_from_memory",
            "memory_read",
        }
        assert set(expected_output.explanation.why_keys) == {
            "caller_pushed_arguments",
            "ebp_relative_access",
        }
        assert set(expected_output.explanation.interpretation_keys) == {
            "argument_location",
            "cdecl_argument_order",
        }


def test_calling_conventions_fixture_requires_argument_labels_only() -> None:
    fixture = GoldenLessonFixture.model_validate(yaml.safe_load(FIXTURE_PATH.read_text()))

    inspect_view = fixture.steps[2].expected_output.inspect_views[0]
    stack_section = inspect_view.sections[0]

    assert isinstance(stack_section, StackRangeSection)
    argument_entries = [entry for entry in stack_section.entries if entry.role is StackRole.ARGUMENT]
    assert [entry.label for entry in argument_entries] == [
        "argument_1",
        "argument_2",
        "argument_3",
    ]
    assert [entry.symbolic_value for entry in argument_entries] == [
        "argument_1",
        "argument_2",
        "argument_3",
    ]
