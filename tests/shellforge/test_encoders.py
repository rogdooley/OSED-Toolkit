from shellforge.analysis.badchars import contains_badchars
from shellforge.encoders.xor import XorEncoder, decode_xor, encode_xor
from shellforge.payloads.fixtures import BENIGN_FIXTURE_BYTES


def test_xor_round_trip_with_manual_key() -> None:
    key = 0x5A
    encoded = encode_xor(BENIGN_FIXTURE_BYTES, key)
    assert decode_xor(encoded, key) == BENIGN_FIXTURE_BYTES


def test_xor_encoder_auto_key_avoids_badchars() -> None:
    encoder = XorEncoder()
    encoded, metadata = encoder.encode(BENIGN_FIXTURE_BYTES, badchars=b"\x00\x0a\x0d")
    assert contains_badchars(encoded, b"\x00\x0a\x0d") is False
    assert encoder.decode(encoded, metadata) == BENIGN_FIXTURE_BYTES
