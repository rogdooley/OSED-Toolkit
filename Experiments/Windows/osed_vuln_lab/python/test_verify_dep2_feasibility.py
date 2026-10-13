from __future__ import annotations

import unittest

from verify_dep2_feasibility import FeasibilityError, validate_transcript


class Dep2FeasibilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.expected = {
            "saved_eip": 0x62501002,
            "pivot_eip": 0x62501014,
            "stage_base": 0x62504000,
            "stage2_offset": 0x100,
            "stage2_first_dword": 0x62501003,
            "proof_address": 0x62504200,
        }

    def valid_transcript(self) -> str:
        return "\n".join(
            (
                "DEP2 saved_eip=62501002",
                "DEP2 pivot_eip=62501014",
                "DEP2 post_pivot_esp=62504100",
                "DEP2 post_pivot_ret=62501003",
                "DEP2 pre_pushad_esp=62504200",
            )
        )

    def test_accepts_complete_expected_pivot_path(self) -> None:
        evidence = validate_transcript(self.valid_transcript(), **self.expected)

        self.assertEqual(evidence.post_pivot_esp, 0x62504100)
        self.assertEqual(evidence.pre_pushad_esp, 0x62504200)

    def test_rejects_wrong_saved_eip(self) -> None:
        transcript = self.valid_transcript().replace("62501002", "41414141")

        with self.assertRaisesRegex(FeasibilityError, "saved EIP"):
            validate_transcript(transcript, **self.expected)

    def test_rejects_missing_pivot_execution(self) -> None:
        transcript = self.valid_transcript().replace("62501014", "62501002")

        with self.assertRaisesRegex(FeasibilityError, "pivot"):
            validate_transcript(transcript, **self.expected)

    def test_rejects_post_pivot_esp_outside_stage(self) -> None:
        transcript = self.valid_transcript().replace("62504100", "62506000")

        with self.assertRaisesRegex(FeasibilityError, "staged chain"):
            validate_transcript(transcript, **self.expected)

    def test_rejects_wrong_first_staged_return(self) -> None:
        transcript = self.valid_transcript().replace("62501003", "62501004")

        with self.assertRaisesRegex(FeasibilityError, "first staged RET"):
            validate_transcript(transcript, **self.expected)

    def test_rejects_pre_pushad_esp_that_is_not_the_proof_address(self) -> None:
        transcript = self.valid_transcript().replace("62504200", "62504204")

        with self.assertRaisesRegex(FeasibilityError, "pre-PUSHAD ESP"):
            validate_transcript(transcript, **self.expected)


if __name__ == "__main__":
    unittest.main()
