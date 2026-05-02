from __future__ import annotations

from shellforge.interfaces import TargetBackend
from shellforge.model import Architecture, BuildArtifact


class WindowsX86Target(TargetBackend):
    name = "windows_x86"
    architecture = Architecture.X86

    def package(self, payload_name: str, payload_bytes: bytes, nasm_source: str) -> BuildArtifact:
        return BuildArtifact(
            payload_name=payload_name,
            architecture=self.architecture,
            payload_bytes=payload_bytes,
            nasm_source=nasm_source,
            metadata={"target": self.name},
        )
