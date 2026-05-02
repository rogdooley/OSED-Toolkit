from __future__ import annotations

from shellforge.interfaces import PayloadProvider
from shellforge.model import Architecture


class DynamicResolverPayloadProvider(PayloadProvider):
    name = "resolver"
    description = "Stub for dynamic API resolver shellcode."

    @property
    def supported_architectures(self) -> frozenset[Architecture]:
        return frozenset({Architecture.X86, Architecture.X64})

    def build_payload(self, architecture: Architecture) -> tuple[bytes, str]:
        raise NotImplementedError(
            "TODO: dynamic API resolver payload is intentionally disabled in analysis-only mode."
        )
