from __future__ import annotations

from shellforge.interfaces import PayloadProvider
from shellforge.model import Architecture


class CalcPayloadProvider(PayloadProvider):
    name = "calc"
    description = "Stub for a Windows API execution payload."

    @property
    def supported_architectures(self) -> frozenset[Architecture]:
        return frozenset({Architecture.X86})

    def build_payload(self, architecture: Architecture) -> tuple[bytes, str]:
        raise NotImplementedError(
            "TODO: calc payload is intentionally disabled. "
            "Do not generate WinExec/CreateProcess/dynamic resolver shellcode in this framework."
        )
