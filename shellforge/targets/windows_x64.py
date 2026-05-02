from __future__ import annotations

from shellforge.interfaces import TargetBackend
from shellforge.model import Architecture, BuildArtifact


class WindowsX64Target(TargetBackend):
    name = "windows_x64"
    architecture = Architecture.X64

    def package(self, payload_name: str, payload_bytes: bytes, nasm_source: str) -> BuildArtifact:
        raise NotImplementedError("Windows x64 target backend is intentionally not implemented in v1")
