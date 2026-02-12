from dataclasses import dataclass, field
from typing import Literal, Optional


ArchType = Literal["x86", "x64"]
ConfidenceType = Literal["high", "medium", "low"]


@dataclass(frozen=True)
class RegisterValue:
    name: str
    value_hex: str
    width_bytes: int
    source_line: str


@dataclass(frozen=True)
class ParsedCrash:
    registers: list[RegisterValue] = field(default_factory=list)
    exception: Optional[str] = None
    exception_values: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Candidate:
    register: Optional[str]
    value_hex: str
    source_line: str
    priority: int
    confidence: ConfidenceType
    reason: str


@dataclass(frozen=True)
class Recommendation:
    query: str
    raw: bool
    command: str
    based_on: str


@dataclass(frozen=True)
class TriageResult:
    detected_arch: ArchType
    endianness: str
    exception: Optional[str]
    candidates: list[Candidate]
    recommendations: list[Recommendation]
    notes: list[str]
