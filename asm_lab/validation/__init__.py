"""Validation utilities for ASM-Lab lesson assertions and fixtures."""

from .assertions import (
    validate_explanation_assertions,
    validate_memory_assertions,
    validate_register_assertions,
    validate_stack_assertions,
    validate_step_assertions,
)
from .fixture_compare import compare_fixture_output, compare_inspect_output
from .results import AssertionFailure, AssertionValidationResult

__all__ = [
    "AssertionFailure",
    "AssertionValidationResult",
    "compare_fixture_output",
    "compare_inspect_output",
    "validate_explanation_assertions",
    "validate_memory_assertions",
    "validate_register_assertions",
    "validate_stack_assertions",
    "validate_step_assertions",
]
