from __future__ import annotations

import string


def printable_ratio(data: bytes) -> float:
    if not data:
        return 1.0
    printable = set(string.printable.encode("ascii"))
    return sum(1 for byte in data if byte in printable) / len(data)


def is_mostly_printable(data: bytes, threshold: float = 0.85) -> bool:
    return printable_ratio(data) >= threshold
