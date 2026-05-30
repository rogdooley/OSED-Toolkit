import os
import sys

import pytest

HERE = os.path.dirname(__file__)
REPO_ROOT = os.path.abspath(os.path.join(HERE, ".."))
TOOLS_DIR = os.path.join(REPO_ROOT, "Tools")
if TOOLS_DIR not in sys.path:
    sys.path.insert(0, TOOLS_DIR)

from badchars_wds.analyzer import (
    compare_observed,
    generate_candidate_bytes,
    validate_magic,
)
from badchars_wds.models import Divergence, Match, Truncated


def test_generate_candidate_bytes_excludes_values():
    out = generate_candidate_bytes(set([0x00, 0x0A, 0xFF]))
    assert len(out) == 253
    assert 0x00 not in out
    assert 0x0A not in out
    assert 0xFF not in out
    assert out[0] == 0x01


def test_generate_candidate_bytes_invalid_set_type():
    with pytest.raises(TypeError):
        generate_candidate_bytes([0x00])  # type: ignore[arg-type]


def test_generate_candidate_bytes_invalid_value_range():
    with pytest.raises(ValueError):
        generate_candidate_bytes(set([256]))


def test_validate_magic_accepts_valid_magic():
    validate_magic(b"\xbc\xf0\xbc\xf0", set([0x00, 0x0A]))


def test_validate_magic_rejects_empty_magic():
    with pytest.raises(ValueError):
        validate_magic(b"", set())


def test_validate_magic_rejects_excluded_magic_byte():
    with pytest.raises(ValueError) as exc:
        validate_magic(b"\xbc\xf0", set([0xF0]))
    assert "0xf0" in str(exc.value).lower()


def test_compare_observed_match():
    result = compare_observed(b"\x01\x02\x03", b"\x01\x02\x03")
    assert isinstance(result, Match)
    assert result.kind == "match"


def test_compare_observed_truncated():
    result = compare_observed(b"\x01\x02\x03\x04", b"\x01\x02")
    assert isinstance(result, Truncated)
    assert result.kind == "truncated"
    assert result.offset == 2
    assert result.expected_byte == 0x03
    assert result.remaining_expected_len == 2
    assert result.observed_len == 2


def test_compare_observed_divergence_first_mismatch():
    result = compare_observed(b"\x10\x20\x30\x40", b"\x10\x99\x30\x40")
    assert isinstance(result, Divergence)
    assert result.kind == "divergence"
    assert result.offset == 1
    assert result.expected_byte == 0x20
    assert result.actual_byte == 0x99
    assert result.remaining_expected_len == 3
    assert result.observed_len == 4


def test_compare_observed_ignores_trailing_observed_bytes():
    result = compare_observed(b"\x01\x02", b"\x01\x02\x03")
    assert isinstance(result, Match)


def test_compare_observed_rejects_non_bytes():
    with pytest.raises(TypeError):
        compare_observed("abc", b"abc")  # type: ignore[arg-type]
