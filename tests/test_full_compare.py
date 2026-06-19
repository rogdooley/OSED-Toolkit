"""
Unit tests for analyzer.full_compare() — the single-shot positional comparison
used for in-place / transform-preserving targets (e.g. Vulnserver LTER).

Pure logic; no debugger or network required.
"""

import os
import sys
import unittest

HERE = os.path.dirname(__file__)
REPO_ROOT = os.path.abspath(os.path.join(HERE, ".."))
TOOLS_DIR = os.path.join(REPO_ROOT, "Tools")
if TOOLS_DIR not in sys.path:
    sys.path.insert(0, TOOLS_DIR)

from badchars_wds.analyzer import full_compare, generate_candidate_bytes

EXCLUDED = {0x00, 0x0A, 0x0D}


class TestCleanDump(unittest.TestCase):
    def test_all_bytes_preserved(self):
        expected = generate_candidate_bytes(EXCLUDED)
        result = full_compare(expected, expected)
        self.assertEqual(result.allowed_bytes, list(expected))
        self.assertEqual(result.transformed_bytes, [])
        self.assertEqual(result.missing_bytes, [])
        self.assertEqual(result.unusable_bytes, [])
        self.assertIsNone(result.detected_transform)
        self.assertIsNone(result.first_mismatch_offset)
        self.assertEqual(result.expected_len, len(expected))
        self.assertEqual(result.observed_len, len(expected))


class TestLterAsciiFold(unittest.TestCase):
    def test_fold_classifies_high_range_and_detects_pattern(self):
        expected = generate_candidate_bytes(EXCLUDED)
        # LTER: bytes >= 0x80 fold to sent - 0x7f; low bytes untouched.
        observed = bytes((b if b < 0x80 else b - 0x7F) for b in expected)
        result = full_compare(expected, observed)

        self.assertEqual(
            result.allowed_bytes,
            [b for b in range(1, 0x80) if b not in (0x0A, 0x0D)],
        )
        self.assertEqual(result.transformed_bytes, list(range(0x80, 0x100)))
        self.assertEqual(result.missing_bytes, [])
        self.assertEqual(result.unusable_bytes, list(range(0x80, 0x100)))
        self.assertIsNotNone(result.detected_transform)
        self.assertIn("ASCII fold", result.detected_transform)


class TestHighBitStrip(unittest.TestCase):
    def test_strip_detected(self):
        expected = generate_candidate_bytes(EXCLUDED)
        observed = bytes((b & 0x7F) for b in expected)
        result = full_compare(expected, observed)
        # 0x01..0x7f with high bit clear are unchanged; >=0x80 get masked.
        self.assertIsNotNone(result.detected_transform)
        self.assertIn("High-bit strip", result.detected_transform)


class TestTruncation(unittest.TestCase):
    def test_short_observation_marks_tail_missing(self):
        expected = generate_candidate_bytes(EXCLUDED)
        observed = expected[:100]  # rest dropped
        result = full_compare(expected, observed)
        self.assertEqual(result.allowed_bytes, list(expected[:100]))
        self.assertEqual(result.missing_bytes, list(expected[100:]))
        self.assertEqual(result.transformed_bytes, [])
        self.assertEqual(result.first_mismatch_offset, 100)
        # A pure-truncation tail is not a systematic transform.
        self.assertIsNone(result.detected_transform)


class TestDiscreteCorruption(unittest.TestCase):
    def test_non_systematic_mismatch_has_no_transform(self):
        expected = generate_candidate_bytes(EXCLUDED)
        observed = bytearray(expected)
        observed[5] = 0xFF       # one arbitrary in-place change
        result = full_compare(expected, bytes(observed))
        self.assertEqual(result.transformed_bytes, [expected[5]])
        self.assertEqual(result.missing_bytes, [])
        self.assertIsNone(result.detected_transform)
        self.assertEqual(result.first_mismatch_offset, 5)


if __name__ == "__main__":
    unittest.main()
