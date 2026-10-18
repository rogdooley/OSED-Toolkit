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
        self.assertIn("event_runtime_initialize", helper)
        self.assertIn("event_runtime_submit", helper)
        self.assertIn("GetProcAddress", helper)
        self.assertNotIn("VirtualProtect(", helper)

    def test_public_header_uses_application_vocabulary(self) -> None:
        header = (ROOT / "include" / "osedhelper.h").read_text(encoding="utf-8")
        helper = (ROOT / "src" / "osedhelper.c").read_text(encoding="utf-8")

        for name in (
            "event_counter_add",
            "event_record_checksum",
            "event_runtime_get_info",
            "event_runtime_check_compatibility",
            "event_runtime_report_status",
            "event_runtime_initialize",
            "event_runtime_submit",
        ):
            self.assertIn(name, header)

        for spoiler in (
            "helper_probe",
            "helper_prepare_rop_runtime",
            "helper_stage_record",
            "helper_get_anchor",
            "helper_aslr_proof",
        ):
            self.assertNotIn(spoiler, header)

        self.assertIn("return &event_runtime_info;", helper)
        self.assertNotIn("return (void *)&event_runtime_get_info", helper)

    def test_training_primitives_are_not_named_exports(self) -> None:
        gadgets = (ROOT / "src" / "osedgadgets.c").read_text(encoding="utf-8")

        self.assertNotIn("__declspec(dllexport) volatile DWORD helper_writable_slot", gadgets)
        self.assertNotIn("__declspec(dllexport) BOOL __stdcall helper_memory_protect", gadgets)
        self.assertNotIn(
            "__declspec(dllexport) __declspec(naked) void helper_sequence_",
            gadgets,
        )

    def test_staged_handler_derives_boundary_from_return_address(self) -> None:
        service = (ROOT / "src" / "osed_vulnsvc.c").read_text(encoding="utf-8")

        self.assertIn("handler_rop_staged", service)
        self.assertIn("_AddressOfReturnAddress", service)
        self.assertIn("3 * sizeof(uint32_t)", service)

    def test_aslr_profile_uses_application_status_export(self) -> None:
        helper = (ROOT / "src" / "osedhelper.c").read_text(encoding="utf-8")

        self.assertIn("#if defined(OSED_PROFILE_ASLR_DEP)", helper)
        self.assertIn("event_runtime_report_status", helper)

    def test_verifier_recognizes_staged_profiles(self) -> None:
        self.assertIn("dep2", PROFILE_EXPECTATIONS)
        self.assertIn("aslr_dep2", PROFILE_EXPECTATIONS)

    def test_verifier_requires_staging_without_direct_dispatch(self) -> None:
        for profile in ("dep2", "aslr_dep2"):
            expected = PROFILE_EXPECTATIONS[profile]
            self.assertIn("event_runtime_initialize", expected["required_exports"])
            self.assertIn("event_runtime_submit", expected["required_exports"])
            self.assertIn("helper_sequence_19", expected["forbidden_sequences"])
            self.assertIn("helper_sequence_20", expected["forbidden_sequences"])

    def test_verifier_rejects_exploit_oriented_export_names(self) -> None:
        forbidden = getattr(verify_binaries, "SPOILER_EXPORT_NAMES", set())

        for name in (
            "helper_probe",
            "helper_prepare_rop_runtime",
            "helper_stage_record",
            "helper_memory_protect",
            "helper_writable_slot",
        ):
            self.assertIn(name, forbidden)

    def test_dep3_uses_application_processing_without_synthetic_gadgets(self) -> None:
        cmake = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
        gadgets = (ROOT / "src" / "osedgadgets.c").read_text(encoding="utf-8")
        service = (ROOT / "src" / "osed_vulnsvc.c").read_text(encoding="utf-8")
        helper = (ROOT / "src" / "osedhelper.c").read_text(encoding="utf-8")

        self.assertIn("dep3", cmake)
        self.assertIn("OSED_PROFILE_DEP3", cmake)
        self.assertNotIn("OSED_PROFILE_DEP3", gadgets)
        self.assertNotIn("OSED_PROFILE_DEP3", helper)
        self.assertIn("process_routed_event", service)
        self.assertIn("EVENT_ROUTE_PROTOCOL_MAX", service)
        self.assertIn(
            "#if defined(OSED_PROFILE_DEP2) || defined(OSED_PROFILE_ASLR_DEP2)\n"
            "static void __declspec(noinline) handler_rop_staged",
            service,
        )

    def test_request_logging_resolves_optional_timestamp_once(self) -> None:
        service = (ROOT / "src" / "osed_vulnsvc.c").read_text(encoding="utf-8")

        self.assertIn(
            "#if defined(OSED_PROFILE_DEP3)\n"
            "#define EVENT_ROUTE_STORAGE_BYTES",
            service,
        )
        self.assertIn("request_log_initialize", service)
        self.assertIn("GetProcAddress", service)
        self.assertIn('"GetSystemTimePreciseAsFileTime"', service)
        self.assertIn("GetSystemTimeAsFileTime", service)
        self.assertIn("request_log_write", service)
        self.assertLess(service.index("request_log_initialize()"), service.index("run_server(port)"))

    def test_verifier_requires_dep3_natural_capabilities_only(self) -> None:
        expected = PROFILE_EXPECTATIONS["dep3"]

        self.assertTrue(expected["service_dep"])
        self.assertFalse(expected["service_aslr"])
        self.assertEqual(expected["required_sequences"], set())
        self.assertNotIn("event_runtime_initialize", expected["required_exports"])
        self.assertNotIn("event_runtime_submit", expected["required_exports"])
        self.assertNotIn("helper_memory_protect", expected["required_exports"])

    def test_verifier_rejects_dep3_virtualprotect_infrastructure(self) -> None:
        expected = PROFILE_EXPECTATIONS["dep3"]

        self.assertFalse(expected["allow_virtualprotect"])


if __name__ == "__main__":
    unittest.main()
