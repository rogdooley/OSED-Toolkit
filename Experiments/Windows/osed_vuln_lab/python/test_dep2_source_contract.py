from __future__ import annotations

import unittest
from pathlib import Path

import verify_binaries
from verify_binaries import PROFILE_EXPECTATIONS


ROOT = Path(__file__).resolve().parents[1]


class Dep2SourceContractTests(unittest.TestCase):
    def test_cmake_defines_fixed_and_aslr_staged_profiles(self) -> None:
        cmake = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")

        self.assertIn('Lab profile: easy dep aslr_dep dep2 aslr_dep2 dep3 seh', cmake)
        self.assertIn("OSED_PROFILE_DEP2", cmake)
        self.assertIn("OSED_PROFILE_ASLR_DEP2", cmake)

    def test_helper_uses_private_staging_and_loader_resolution(self) -> None:
        helper = (ROOT / "src" / "osedhelper.c").read_text(encoding="utf-8")

        self.assertIn("OSED_STAGE_BYTES", helper)
        self.assertIn("helper_prepare_rop_runtime", helper)
        self.assertIn("helper_stage_record", helper)
        self.assertIn("GetProcAddress", helper)
        self.assertNotIn("VirtualProtect(", helper)

    def test_staged_handler_derives_boundary_from_return_address(self) -> None:
        service = (ROOT / "src" / "osed_vulnsvc.c").read_text(encoding="utf-8")

        self.assertIn("handler_rop_staged", service)
        self.assertIn("_AddressOfReturnAddress", service)
        self.assertIn("3 * sizeof(uint32_t)", service)

    def test_staged_profiles_do_not_include_the_legacy_aslr_proof_export(self) -> None:
        helper = (ROOT / "src" / "osedhelper.c").read_text(encoding="utf-8")

        self.assertIn("#if defined(OSED_PROFILE_ASLR_DEP)", helper)
        self.assertIn("helper_aslr_proof", helper)

    def test_verifier_recognizes_staged_profiles(self) -> None:
        self.assertIn("dep2", PROFILE_EXPECTATIONS)
        self.assertIn("aslr_dep2", PROFILE_EXPECTATIONS)

    def test_verifier_requires_staging_without_direct_dispatch(self) -> None:
        for profile in ("dep2", "aslr_dep2"):
            expected = PROFILE_EXPECTATIONS[profile]
            self.assertIn("helper_prepare_rop_runtime", expected["required"])
            self.assertIn("helper_stage_record", expected["required"])
            self.assertIn("helper_sequence_19", expected["forbidden"])
            self.assertIn("helper_sequence_20", expected["forbidden"])

    def test_dep3_has_a_distinct_constrained_staged_contract(self) -> None:
        cmake = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
        gadgets = (ROOT / "src" / "osedgadgets.c").read_text(encoding="utf-8")

        self.assertIn("dep3", cmake)
        self.assertIn("OSED_PROFILE_DEP3", cmake)
        self.assertIn("helper_sequence_30", gadgets)
        self.assertIn("pop ecx", gadgets)
        self.assertIn("pop ebp", gadgets)
        self.assertIn("pop edi", gadgets)
        self.assertIn("pop eax", gadgets)
        self.assertIn("xchg eax, edx", gadgets)
        self.assertIn("neg eax", gadgets)
        self.assertIn("[eax + 0x10]", gadgets)
        self.assertIn("add esp, 0x1C", gadgets)
        self.assertIn("helper_sequence_41", gadgets)
        self.assertIn("helper_sequence_42", gadgets)

    def test_verifier_requires_dep3_side_effect_gadgets(self) -> None:
        expected = PROFILE_EXPECTATIONS["dep3"]

        self.assertTrue(expected["service_dep"])
        self.assertFalse(expected["service_aslr"])
        self.assertIn("helper_sequence_30", expected["required"])
        self.assertIn("helper_sequence_32", expected["required"])
        self.assertIn("helper_sequence_33", expected["required"])
        self.assertIn("helper_sequence_34", expected["required"])
        self.assertIn("helper_sequence_41", expected["required"])
        self.assertIn("helper_sequence_42", expected["required"])
        self.assertIn("helper_sequence_43", expected["required"])
        self.assertIn("helper_sequence_01", expected["forbidden"])
        self.assertIn("helper_memory_protect", expected["forbidden"])

    def test_verifier_rejects_clean_dep3_register_loaders(self) -> None:
        forbidden = getattr(verify_binaries, "DEP3_FORBIDDEN_BYTES", {})

        for sequence in (b"\x59\xC3", b"\x5B\xC3", b"\x5E\xC3", b"\x5F\xC3"):
            self.assertIn(sequence, forbidden)


if __name__ == "__main__":
    unittest.main()
