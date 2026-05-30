"""Core byte-generation and comparison utilities."""

from typing import Set

from .models import Divergence, Match, Truncated


def generate_candidate_bytes(excluded):  # type: (Set[int]) -> bytes
    """
    Generate deterministic candidate bytes [0x00..0xFF] excluding known values.
    """
    _validate_excluded_values(excluded)
    return bytes(value for value in range(256) if value not in excluded)


def validate_magic(magic, excluded):  # type: (bytes, Set[int]) -> None
    """
    Validate that magic bytes are usable with current exclusion set.
    """
    if not isinstance(magic, (bytes, bytearray)):
        raise TypeError("magic must be bytes-like")
    if len(magic) == 0:
        raise ValueError("magic must not be empty")

    _validate_excluded_values(excluded)

    for byte_value in magic:
        if byte_value in excluded:
            raise ValueError("magic byte 0x{0:02x} is excluded".format(byte_value))


def compare_observed(expected, observed):  # type: (bytes, bytes)
    """
    Compare observed bytes to expected bytes with detailed diagnostics.
    """
    if not isinstance(expected, (bytes, bytearray)):
        raise TypeError("expected must be bytes-like")
    if not isinstance(observed, (bytes, bytearray)):
        raise TypeError("observed must be bytes-like")

    expected_len = len(expected)
    observed_len = len(observed)

    limit = observed_len if observed_len < expected_len else expected_len
    for index in range(limit):
        exp = expected[index]
        act = observed[index]
        if exp != act:
            return Divergence(
                offset=index,
                expected_byte=exp,
                actual_byte=act,
                remaining_expected_len=expected_len - index,
                observed_len=observed_len,
            )

    if observed_len < expected_len:
        return Truncated(
            offset=observed_len,
            expected_byte=expected[observed_len],
            remaining_expected_len=expected_len - observed_len,
            observed_len=observed_len,
        )

    return Match()


def _validate_excluded_values(excluded):  # type: (Set[int]) -> None
    if excluded is None:
        raise TypeError("excluded must be a set of integers")
    if not isinstance(excluded, set):
        raise TypeError("excluded must be a set of integers")
    for value in excluded:
        if not isinstance(value, int):
            raise TypeError("excluded must contain only integers")
        if value < 0 or value > 255:
            raise ValueError("excluded values must be in byte range 0..255")
