from __future__ import annotations


def parse_badchars(raw: str) -> bytes:
    if not raw:
        return b""
    parts = [piece.strip().lower() for piece in raw.split(",") if piece.strip()]
    values: list[int] = []
    for part in parts:
        token = part.removeprefix("0x")
        if len(token) != 2:
            raise ValueError(f"invalid badchar token: {part}")
        values.append(int(token, 16))
    return bytes(values)


def find_badchars(data: bytes, badchars: bytes) -> list[int]:
    bad = set(badchars)
    return [index for index, byte in enumerate(data) if byte in bad]


def contains_badchars(data: bytes, badchars: bytes) -> bool:
    return bool(find_badchars(data, badchars))
