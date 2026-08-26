"""Tests for Tools.peinfo analyzer."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from Tools.peinfo.analyzer import (
    PEAnalyzer,
    PEReport,
    _count_pattern,
    _count_add_esp_ret,
)


# ---------------------------------------------------------------------------
# Fixtures: build minimal PE files in-memory and write to tmp_path
# ---------------------------------------------------------------------------

def _make_pe(
    tmp_path: Path,
    name: str = "test.exe",
    dll_characteristics: int = 0x0000,
    machine: int = 0x014C,
    text_payload: bytes = b"",
    add_reloc: bool = False,
) -> Path:
    """Build a minimal PE32 with controllable DllCharacteristics and .text payload."""
    dos_header = bytearray(128)
    dos_header[0:2] = b"MZ"
    struct.pack_into("<I", dos_header, 60, 128)

    signature = b"PE\x00\x00"

    num_sections = 3 if add_reloc else 2
    file_header = struct.pack(
        "<HHIIIHH",
        machine, num_sections,
        0x4BB7D570, 0, 0,
        0xE0, 0x0102,
    )

    optional_header = bytearray(0xE0)
    struct.pack_into("<H", optional_header, 0, 0x010B)
    optional_header[2] = 10
    struct.pack_into("<I", optional_header, 16, 0x1000)
    struct.pack_into("<I", optional_header, 28, 0x00400000)
    struct.pack_into("<I", optional_header, 32, 0x1000)
    struct.pack_into("<I", optional_header, 36, 0x200)
    struct.pack_into("<I", optional_header, 56, 0x6000 if add_reloc else 0x5000)
    struct.pack_into("<I", optional_header, 60, 0x200)
    struct.pack_into("<H", optional_header, 70, dll_characteristics)
    struct.pack_into("<I", optional_header, 72, 0x100000)
    struct.pack_into("<I", optional_header, 76, 0x1000)
    struct.pack_into("<I", optional_header, 80, 0x100000)
    struct.pack_into("<I", optional_header, 84, 0x1000)
    struct.pack_into("<I", optional_header, 92, 16)

    text_hdr = bytearray(40)
    text_hdr[0:6] = b".text\x00"
    struct.pack_into("<I", text_hdr, 8, 0x1000)
    struct.pack_into("<I", text_hdr, 12, 0x1000)
    struct.pack_into("<I", text_hdr, 16, 0x200)
    struct.pack_into("<I", text_hdr, 20, 0x200)
    struct.pack_into("<I", text_hdr, 36, 0x60000020)

    data_hdr = bytearray(40)
    data_hdr[0:6] = b".data\x00"
    struct.pack_into("<I", data_hdr, 8, 0x1000)
    struct.pack_into("<I", data_hdr, 12, 0x2000)
    struct.pack_into("<I", data_hdr, 16, 0x200)
    struct.pack_into("<I", data_hdr, 20, 0x400)
    struct.pack_into("<I", data_hdr, 36, 0xC0000040)

    section_hdrs = text_hdr + data_hdr

    if add_reloc:
        reloc_hdr = bytearray(40)
        reloc_hdr[0:6] = b".reloc"
        struct.pack_into("<I", reloc_hdr, 8, 0x1000)
        struct.pack_into("<I", reloc_hdr, 12, 0x3000)
        struct.pack_into("<I", reloc_hdr, 16, 0x200)
        struct.pack_into("<I", reloc_hdr, 20, 0x600)
        struct.pack_into("<I", reloc_hdr, 36, 0x42000040)
        section_hdrs += reloc_hdr

    headers = dos_header + signature + file_header + optional_header + section_hdrs
    headers = headers.ljust(0x200, b"\x00")

    text_data = bytearray(0x200)
    text_data[:len(text_payload)] = text_payload

    data_section = bytearray(0x200)

    pe_bytes = headers + text_data + data_section
    if add_reloc:
        pe_bytes += bytearray(0x200)

    out = tmp_path / name
    out.write_bytes(pe_bytes)
    return out


# ---------------------------------------------------------------------------
# Unit tests for byte-pattern helpers
# ---------------------------------------------------------------------------

class TestPatternHelpers:
    def test_count_pattern_single(self):
        assert _count_pattern(b"\xc3\x00\xc3", b"\xc3") == 2

    def test_count_pattern_overlapping(self):
        assert _count_pattern(b"\xc3\xc3\xc3", b"\xc3") == 3

    def test_count_pattern_empty(self):
        assert _count_pattern(b"\x00\x00\x00", b"\xc3") == 0

    def test_count_add_esp_ret_imm8(self):
        data = b"\x83\xc4\x10\xc3"
        assert _count_add_esp_ret(data) == 1

    def test_count_add_esp_ret_imm32(self):
        data = b"\x81\xc4\x00\x01\x00\x00\xc3"
        assert _count_add_esp_ret(data) == 1

    def test_count_add_esp_ret_no_ret(self):
        data = b"\x83\xc4\x10\x90"
        assert _count_add_esp_ret(data) == 0


# ---------------------------------------------------------------------------
# Integration tests against minimal PEs
# ---------------------------------------------------------------------------

class TestPEAnalyzer:
    def test_basic_analysis(self, tmp_path):
        pe_path = _make_pe(tmp_path)
        with PEAnalyzer(pe_path) as a:
            report = a.analyze()
        assert isinstance(report, PEReport)
        assert report.file_info.machine == "x86 (I386)"
        assert report.file_info.machine_raw == 0x014C

    def test_no_mitigations(self, tmp_path):
        pe_path = _make_pe(tmp_path, dll_characteristics=0x0000)
        with PEAnalyzer(pe_path) as a:
            report = a.analyze()
        mit = report.mitigations
        assert not mit.nx_compat
        assert not mit.dynamic_base
        assert not mit.high_entropy_va
        assert not mit.guard_cf
        assert not mit.no_seh

    def test_nx_compat_set(self, tmp_path):
        pe_path = _make_pe(tmp_path, dll_characteristics=0x0100)
        with PEAnalyzer(pe_path) as a:
            report = a.analyze()
        assert report.mitigations.nx_compat
        assert not report.mitigations.dynamic_base

    def test_dynamic_base_set(self, tmp_path):
        pe_path = _make_pe(tmp_path, dll_characteristics=0x0040)
        with PEAnalyzer(pe_path) as a:
            report = a.analyze()
        assert report.mitigations.dynamic_base

    def test_all_mitigations(self, tmp_path):
        dc = 0x0100 | 0x0040 | 0x0020 | 0x4000 | 0x0400
        pe_path = _make_pe(tmp_path, dll_characteristics=dc)
        with PEAnalyzer(pe_path) as a:
            report = a.analyze()
        mit = report.mitigations
        assert mit.nx_compat
        assert mit.dynamic_base
        assert mit.high_entropy_va
        assert mit.guard_cf
        assert mit.no_seh

    def test_sections(self, tmp_path):
        pe_path = _make_pe(tmp_path)
        with PEAnalyzer(pe_path) as a:
            report = a.analyze()
        names = [s.name for s in report.sections]
        assert ".text" in names
        assert ".data" in names
        text = next(s for s in report.sections if s.name == ".text")
        assert text.executable
        assert text.readable
        assert not text.writable

    def test_reloc_section_detection(self, tmp_path):
        pe_no_reloc = _make_pe(tmp_path, name="no_reloc.exe", add_reloc=False)
        pe_reloc = _make_pe(tmp_path, name="has_reloc.exe", add_reloc=True)

        with PEAnalyzer(pe_no_reloc) as a:
            r1 = a.analyze()
        with PEAnalyzer(pe_reloc) as a:
            r2 = a.analyze()

        assert not r1.mitigations.relocations_present
        assert r2.mitigations.relocations_present

    def test_memory_layout(self, tmp_path):
        pe_path = _make_pe(tmp_path)
        with PEAnalyzer(pe_path) as a:
            report = a.analyze()
        ml = report.memory_layout
        assert ml["image_base"] == 0x00400000
        assert ml["entry_point"] == 0x00401000
        assert ml["section_alignment"] == 0x1000
        assert ml["file_alignment"] == 0x200

    def test_gadget_counting(self, tmp_path):
        payload = (
            b"\xc3" * 3           # 3 RETs
            + b"\x58\xc3"         # POP EAX; RET
            + b"\xff\xe4"         # JMP ESP
            + b"\x54\xc3"         # PUSH ESP; RET
        )
        pe_path = _make_pe(tmp_path, text_payload=payload)
        with PEAnalyzer(pe_path) as a:
            report = a.analyze()
        gc = report.gadget_counts
        assert gc.ret >= 3
        assert gc.jmp_esp >= 1
        assert gc.push_esp_ret >= 1

    def test_interesting_strings(self, tmp_path):
        payload = b"http://evil.com\x00cmd.exe\x00password123\x00"
        pe_path = _make_pe(tmp_path, text_payload=payload)
        with PEAnalyzer(pe_path) as a:
            report = a.analyze()
        strs = report.interesting_strings
        assert any("http://" in s for s in strs)
        assert any("cmd.exe" in s for s in strs)
        assert any("password" in s for s in strs)

    def test_exploitability_no_mitigations(self, tmp_path):
        payload = b"\xc3" * 100 + b"\xff\xe4"
        pe_path = _make_pe(tmp_path, dll_characteristics=0x0000,
                           text_payload=payload)
        with PEAnalyzer(pe_path) as a:
            report = a.analyze()
        assert report.exploitability.rop_candidate
        assert len(report.exploitability.reasons) > 0
        assert len(report.exploitability.warnings) == 0

    def test_exploitability_hardened(self, tmp_path):
        dc = 0x0100 | 0x0040 | 0x0020 | 0x4000
        pe_path = _make_pe(tmp_path, dll_characteristics=dc)
        with PEAnalyzer(pe_path) as a:
            report = a.analyze()
        assert not report.exploitability.rop_candidate
        assert len(report.exploitability.warnings) > 0

    def test_non_x86_skips_gadgets(self, tmp_path):
        pe_path = _make_pe(tmp_path, machine=0x8664)
        with PEAnalyzer(pe_path) as a:
            report = a.analyze()
        gc = report.gadget_counts
        assert gc.ret == 0
        assert gc.jmp_esp == 0


# ---------------------------------------------------------------------------
# CLI smoke test
# ---------------------------------------------------------------------------

class TestCLI:
    def test_plain_output(self, tmp_path):
        pe_path = _make_pe(tmp_path)
        from Tools.peinfo.cli import main
        import io
        import sys

        old_stdout = sys.stdout
        sys.stdout = buf = io.StringIO()
        try:
            main([str(pe_path), "--plain"])
        finally:
            sys.stdout = old_stdout

        output = buf.getvalue()
        assert "PE Information" in output
        assert "PE Mitigations" in output
        assert "0x00400000" in output

    def test_json_output(self, tmp_path):
        pe_path = _make_pe(tmp_path)
        from Tools.peinfo.cli import main
        import io
        import json
        import sys

        old_stdout = sys.stdout
        sys.stdout = buf = io.StringIO()
        try:
            main([str(pe_path), "--json"])
        finally:
            sys.stdout = old_stdout

        data = json.loads(buf.getvalue())
        assert data["file_info"]["machine"] == "x86 (I386)"
        assert "mitigations" in data
        assert "gadget_counts" in data

    def test_missing_file(self, tmp_path):
        from Tools.peinfo.cli import main
        with pytest.raises(SystemExit) as exc:
            main([str(tmp_path / "nonexistent.exe")])
        assert exc.value.code == 1
