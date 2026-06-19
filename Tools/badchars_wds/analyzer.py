"""Core byte-generation and comparison utilities."""

from dataclasses import dataclass, field
from typing import List, Optional, Set

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


# ---------------------------------------------------------------------------
# Single-shot full comparison (mona !cmp equivalent)
# ---------------------------------------------------------------------------
#
# compare_observed() above is the iterative primitive: it stops at the first
# divergence so the orchestrator can exclude that byte and resend. That is the
# right model for *truncating* bad chars (e.g. 0x00 terminates a strcpy and
# everything after it is lost), where you genuinely cannot see past the bad
# byte without removing it.
#
# full_compare() is the opposite model: it assumes the observed buffer is
# positionally aligned with what was sent (no bytes dropped) and classifies
# EVERY candidate in one pass. This handles in-place corruption — most
# importantly ASCII-folding targets like Vulnserver's LTER, where bytes >= 0x80
# are transformed but nothing is dropped — and produces the same complete
# verdict that `!mona cmp` gives from a single dump, with no iteration.


@dataclass
class ByteVerdict:
    """Per-candidate outcome from a positional comparison."""
    sent: int
    observed: Optional[int]   # None when the buffer ended before this index
    status: str               # "ok" | "transformed" | "missing"


@dataclass
class FullComparison:
    """
    Explicit, observable contract for a single-shot positional comparison.

    Categories are deliberately distinct rather than collapsed into one
    "bad chars" list, because the operator decision differs:
      - transformed_bytes : present but mangled in place (e.g. ASCII fold).
      - missing_bytes     : absent — the observation ended before this index,
                            which is the *truncation* signature and usually
                            means full_compare() is the wrong tool (use the
                            iterative orchestrator instead).
    unusable_bytes is the union, for the "do not place these in shellcode"
    answer. detected_transform is set only when the mismatches fit a known
    systematic model across the whole affected range.
    """
    verdicts: List[ByteVerdict] = field(default_factory=list)
    allowed_bytes: List[int] = field(default_factory=list)       # preserved
    transformed_bytes: List[int] = field(default_factory=list)   # mangled in place
    missing_bytes: List[int] = field(default_factory=list)       # absent / truncated
    expected_len: int = 0
    observed_len: int = 0
    aligned_len: int = 0                                          # bytes compared
    first_mismatch_offset: Optional[int] = None
    detected_transform: Optional[str] = None

    @property
    def unusable_bytes(self):  # type: () -> List[int]
        return sorted(set(self.transformed_bytes) | set(self.missing_bytes))


def full_compare(expected, observed):  # type: (bytes, bytes) -> FullComparison
    """
    Classify every expected byte against a positionally-aligned observation.

    Unlike compare_observed(), this does not stop at the first mismatch and
    does not attempt to realign after a dropped byte — it mirrors how
    `!mona cmp` reports an in-place comparison. Use it when the target mangles
    bytes in place (transforms) rather than truncating the copy.
    """
    if not isinstance(expected, (bytes, bytearray)):
        raise TypeError("expected must be bytes-like")
    if not isinstance(observed, (bytes, bytearray)):
        raise TypeError("observed must be bytes-like")

    result = FullComparison()
    result.expected_len = len(expected)
    result.observed_len = len(observed)

    for index, sent in enumerate(expected):
        if index < len(observed):
            obs = observed[index]
            if obs == sent:
                result.verdicts.append(ByteVerdict(sent, obs, "ok"))
                result.allowed_bytes.append(sent)
            else:
                result.verdicts.append(ByteVerdict(sent, obs, "transformed"))
                result.transformed_bytes.append(sent)
                if result.first_mismatch_offset is None:
                    result.first_mismatch_offset = index
        else:
            result.verdicts.append(ByteVerdict(sent, None, "missing"))
            result.missing_bytes.append(sent)
            if result.first_mismatch_offset is None:
                result.first_mismatch_offset = index

    result.aligned_len = min(len(expected), len(observed))
    result.detected_transform = _detect_transform(result.verdicts)
    return result


def _detect_transform(verdicts):  # type: (List[ByteVerdict]) -> Optional[str]
    """
    Recognise a systematic in-place transform across the mismatching bytes.

    Currently detects the ASCII fold seen on Vulnserver LTER (every high byte
    mapped to sent-0x7f) and the 7-bit strip (sent & 0x7f). Returns a human
    note or None when mismatches look like discrete, unrelated bad chars.
    """
    transformed = [v for v in verdicts if v.status == "transformed"]
    if not transformed:
        return None

    if all(v.observed == v.sent - 0x7F for v in transformed):
        return ("ASCII fold detected: every corrupted byte maps to sent-0x7f "
                "(0x80->0x01 ... 0xff->0x80). Only 0x01-0x7f survive; treat the "
                "target as ASCII-only.")
    if all(v.observed == (v.sent & 0x7F) for v in transformed):
        return ("High-bit strip detected: corrupted bytes are masked with 0x7f. "
                "Treat the target as 7-bit/ASCII-only.")
    return None


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
