from __future__ import annotations

from shellforge.analysis.badchars import contains_badchars
from shellforge.model import BuildArtifact, BuildRequest
from shellforge.payloads.egg import apply_egg_marker
from shellforge.registry import get_payload_providers, get_targets


class ShellcodeBuilder:
    def __init__(self) -> None:
        self._targets = get_targets()
        self._payload_providers = get_payload_providers()

    @property
    def payload_names(self) -> tuple[str, ...]:
        return tuple(sorted(self._payload_providers.keys()))

    def build(self, request: BuildRequest) -> BuildArtifact:
        target = self._targets.get(request.architecture.value)
        if target is None:
            raise ValueError(f"unsupported architecture: {request.architecture.value}")

        provider = self._payload_providers.get(request.payload)
        if provider is None:
            raise ValueError(f"unknown payload provider: {request.payload}")

        payload_bytes, nasm_source = provider.build_payload(request.architecture)
        payload_bytes = apply_egg_marker(payload_bytes, request.egg_marker)
        if contains_badchars(payload_bytes, request.badchars):
            raise ValueError("built payload contains requested badchars")
        return target.package(provider.name, payload_bytes, nasm_source)
