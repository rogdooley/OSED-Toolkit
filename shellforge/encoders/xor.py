from __future__ import annotations

from shellforge.analysis.badchars import contains_badchars
from shellforge.interfaces import Encoder


def _candidate_keys() -> range:
    return range(1, 256)


def select_xor_key(data: bytes, badchars: bytes) -> int:
    for key in _candidate_keys():
        encoded = encode_xor(data, key)
        if key in badchars:
            continue
        if not contains_badchars(encoded, badchars):
            return key
    raise ValueError("no XOR key can encode payload without requested badchars")


def encode_xor(data: bytes, key: int) -> bytes:
    if not 0 <= key <= 0xFF:
        raise ValueError("XOR key must be in range 0x00..0xFF")
    return bytes(byte ^ key for byte in data)


def decode_xor(data: bytes, key: int) -> bytes:
    return encode_xor(data, key)


class XorEncoder(Encoder):
    name = "xor"

    def encode(self, data: bytes, *, badchars: bytes = b"") -> tuple[bytes, dict[str, str]]:
        key = select_xor_key(data, badchars)
        encoded = encode_xor(data, key)
        return encoded, {"key": f"{key:02x}"}

    def decode(self, data: bytes, metadata: dict[str, str]) -> bytes:
        key_hex = metadata.get("key")
        if key_hex is None:
            raise ValueError("missing key in metadata")
        return decode_xor(data, int(key_hex, 16))
