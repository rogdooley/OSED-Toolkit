from __future__ import annotations

import zlib

from shellforge.interfaces import HashProvider


def crc32_hash(symbol: str) -> int:
    return zlib.crc32(symbol.encode("ascii", errors="strict")) & 0xFFFFFFFF


class CRC32HashProvider(HashProvider):
    name = "crc32"

    def compute(self, symbol: str) -> int:
        return crc32_hash(symbol)
