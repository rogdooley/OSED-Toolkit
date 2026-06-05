from pathlib import Path

import yaml

from asm_lab.models import GoldenLessonFixture, StackRangeSection, StackRole


FIXTURE_PATH = Path("tests/asm_lab/fixtures/stack_frame_canonical.yaml")


def test_stack_frame_fixture_validates_against_models() -> None:
    fixture = GoldenLessonFixture.model_validate(yaml.safe_load(FIXTURE_PATH.read_text()))

    assert fixture.metadata.title == "Stack Frame - Canonical x86 Prologue"
    assert len(fixture.steps) == 3


def test_stack_frame_fixture_defines_canonical_instruction_sequence() -> None:
    fixture = GoldenLessonFixture.model_validate(yaml.safe_load(FIXTURE_PATH.read_text()))

    assert [step.instruction for step in fixture.steps] == [
        "push ebp",
        "mov ebp, esp",
        "sub esp, 0x20",
    ]


def test_stack_frame_fixture_requires_explanation_contract_keys() -> None:
    fixture = GoldenLessonFixture.model_validate(yaml.safe_load(FIXTURE_PATH.read_text()))

    push_step = fixture.steps[0].expected_output
    mov_step = fixture.steps[1].expected_output
    sub_step = fixture.steps[2].expected_output
    assert push_step is not None
    assert mov_step is not None
    assert sub_step is not None

    assert set(push_step.explanation.why_keys) == {"frame_setup", "stack_growth"}
    assert set(push_step.explanation.interpretation_keys) == {"saved_frame_pointer"}
    assert set(mov_step.explanation.why_keys) == {"frame_pointer_established"}
    assert set(mov_step.explanation.interpretation_keys) == {
        "return_address_location",
        "argument_location",
    }
    assert set(sub_step.explanation.why_keys) == {
        "stack_growth",
        "local_storage_allocated",
    }
    assert set(sub_step.explanation.interpretation_keys) == {
        "local_storage_allocated",
        "saved_frame_pointer",
        "return_address_location",
        "argument_location",
    }


def test_stack_frame_fixture_requires_role_aware_inspection() -> None:
    fixture = GoldenLessonFixture.model_validate(yaml.safe_load(FIXTURE_PATH.read_text()))

    inspect_view = fixture.steps[2].expected_output.inspect_views[0]
    stack_section = inspect_view.sections[0]

    assert isinstance(stack_section, StackRangeSection)
    assert [entry.role for entry in stack_section.entries] == [
        StackRole.LOCAL,
        StackRole.LOCAL,
        StackRole.SAVED_EBP,
        StackRole.RETURN_ADDRESS,
        StackRole.ARGUMENT,
    ]
