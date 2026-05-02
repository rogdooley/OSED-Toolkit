from __future__ import annotations

from shellforge.interfaces import HashProvider


def _ror32(value: int, bits: int) -> int:
    return ((value >> bits) | (value << (32 - bits))) & 0xFFFFFFFF


def ror13_hash(symbol: str) -> int:
    value = 0
    for byte in symbol.encode("ascii", errors="strict"):
        value = _ror32(value, 13)
        value = (value + byte) & 0xFFFFFFFF
    return value


class ROR13HashProvider(HashProvider):
    name = "ror13"

    def compute(self, symbol: str) -> int:
        return ror13_hash(symbol)
