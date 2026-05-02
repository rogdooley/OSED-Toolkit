from __future__ import annotations

from shellforge.interfaces import Encoder


class AlphaEncoder(Encoder):
    name = "alpha"

    def encode(self, data: bytes, *, badchars: bytes = b"") -> tuple[bytes, dict[str, str]]:
        raise NotImplementedError("TODO: implement non-operational alpha encoder")

    def decode(self, data: bytes, metadata: dict[str, str]) -> bytes:
        raise NotImplementedError("TODO: implement non-operational alpha decoder")
