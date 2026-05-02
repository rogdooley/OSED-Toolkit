from __future__ import annotations


def apply_egg_marker(payload: bytes, marker: str | None) -> bytes:
    if marker is None:
        return payload
    tag = marker.encode("ascii", errors="strict")
    if len(tag) != 4:
        raise ValueError("egg marker must be exactly 4 ASCII characters")
    return tag + tag + payload
