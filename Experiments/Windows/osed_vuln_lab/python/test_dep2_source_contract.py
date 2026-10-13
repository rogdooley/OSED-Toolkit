from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class Dep2SourceContractTests(unittest.TestCase):
    def test_cmake_defines_fixed_and_aslr_staged_profiles(self) -> None:
        cmake = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")

        self.assertIn('Lab profile: easy dep aslr_dep dep2 aslr_dep2 seh', cmake)
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


if __name__ == "__main__":
    unittest.main()
