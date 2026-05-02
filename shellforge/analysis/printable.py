from __future__ import annotations

import string


def is_mostly_printable(data: bytes, threshold: float = 0.85) -> bool:
    if not data:
        return True
    printable = set(string.printable.encode("ascii"))
    ratio = sum(1 for byte in data if byte in printable) / len(data)
    return ratio >= threshold
