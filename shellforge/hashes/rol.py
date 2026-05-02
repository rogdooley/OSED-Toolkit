from __future__ import annotations

from shellforge.interfaces import HashProvider


def _rol32(value: int, bits: int) -> int:
    return ((value << bits) | (value >> (32 - bits))) & 0xFFFFFFFF


def rol7_hash(symbol: str) -> int:
    value = 0
    for byte in symbol.encode("ascii", errors="strict"):
        value = _rol32(value, 7)
        value = (value + byte) & 0xFFFFFFFF
    return value


class ROL7HashProvider(HashProvider):
    name = "rol7"

    def compute(self, symbol: str) -> int:
        return rol7_hash(symbol)
