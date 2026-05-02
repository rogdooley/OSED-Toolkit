from __future__ import annotations

from shellforge.model import Architecture
from shellforge.interfaces import PayloadProvider
from shellforge.payloads.fixtures import BENIGN_FIXTURE_BYTES


class DemoPayloadProvider(PayloadProvider):
    name = "demo"
    description = "Harmless marker-byte payload fixture for analysis and formatter testing."

    @property
    def supported_architectures(self) -> frozenset[Architecture]:
        return frozenset({Architecture.X86})

    def build_payload(self, architecture: Architecture) -> tuple[bytes, str]:
        if architecture not in self.supported_architectures:
            raise ValueError(f"payload {self.name} does not support arch={architecture.value}")
        payload = BENIGN_FIXTURE_BYTES
        nasm_reference = "\n".join(
            [
                "BITS 32",
                "global _start",
                "_start:",
                "    ; Placeholder NASM reference for a non-operational payload.",
                "    ; No resolver/API execution logic is intentionally included.",
                "    db 'SAFE_FIXTURE_0123456789'",
            ]
        )
        return payload, nasm_reference
