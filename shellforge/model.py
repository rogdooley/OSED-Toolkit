from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class Architecture(StrEnum):
    X86 = "x86"
    X64 = "x64"


class OutputFormat(StrEnum):
    RAW = "raw"
    HEX_DUMP = "hex"
    PYTHON = "python"
    C_ARRAY = "c"


@dataclass(frozen=True, slots=True)
class BuildRequest:
    payload: str
    architecture: Architecture
    badchars: bytes = b""
    egg_marker: str | None = None


@dataclass(frozen=True, slots=True)
class BuildArtifact:
    payload_name: str
    architecture: Architecture
    payload_bytes: bytes
    nasm_source: str | None = None
    metadata: dict[str, str] = field(default_factory=dict)
