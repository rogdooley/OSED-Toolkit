"""Structured validation result models for ASM-Lab."""

from pydantic import BaseModel, ConfigDict, Field


class AssertionFailure(BaseModel):
    model_config = ConfigDict(frozen=True)

    category: str = Field(min_length=1)
    expected: str = Field(min_length=1)
    actual: str = Field(min_length=1)
    message: str = Field(min_length=1)


class AssertionValidationResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    passed: bool
    failures: list[AssertionFailure] = Field(default_factory=list)
    checked_categories: list[str] = Field(default_factory=list)

    @classmethod
    def empty(cls) -> "AssertionValidationResult":
        return cls(passed=True)

    @classmethod
    def from_failures(
        cls, checked_categories: list[str], failures: list[AssertionFailure]
    ) -> "AssertionValidationResult":
        return cls(
            passed=not failures,
            failures=failures,
            checked_categories=checked_categories,
        )
