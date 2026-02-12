from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class ShellcodeReport:
    length: int
    sha256: str
    md5: str
    badchars: list[int]


def find_badchars(data: bytes, badchars: Iterable[int]) -> list[int]:
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes-like")

    wanted = set(int(b) & 0xFF for b in badchars)
    present = sorted({b for b in data if b in wanted})
    return present


def analyze_shellcode(data: bytes, *, badchars: Iterable[int] = (0x00, 0x0A, 0x0D)) -> ShellcodeReport:
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes-like")
    data = bytes(data)

    sha256 = hashlib.sha256(data).hexdigest()
    md5 = hashlib.md5(data).hexdigest()
    found = find_badchars(data, badchars)

    return ShellcodeReport(
        length=len(data),
        sha256=sha256,
        md5=md5,
        badchars=found,
    )
