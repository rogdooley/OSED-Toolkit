from __future__ import annotations

from abc import ABC, abstractmethod

from shellforge.model import Architecture, BuildArtifact


class PayloadProvider(ABC):
    name: str
    description: str

    @property
    @abstractmethod
    def supported_architectures(self) -> frozenset[Architecture]:
        raise NotImplementedError

    @abstractmethod
    def build_payload(self, architecture: Architecture) -> tuple[bytes, str]:
        raise NotImplementedError


class Encoder(ABC):
    name: str

    @abstractmethod
    def encode(self, data: bytes, *, badchars: bytes = b"") -> tuple[bytes, dict[str, str]]:
        raise NotImplementedError

    @abstractmethod
    def decode(self, data: bytes, metadata: dict[str, str]) -> bytes:
        raise NotImplementedError


class HashProvider(ABC):
    name: str

    @abstractmethod
    def compute(self, symbol: str) -> int:
        raise NotImplementedError


class TargetBackend(ABC):
    name: str
    architecture: Architecture

    @abstractmethod
    def package(self, payload_name: str, payload_bytes: bytes, nasm_source: str) -> BuildArtifact:
        raise NotImplementedError
