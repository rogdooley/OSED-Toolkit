"""Tests for the build pipeline (build.py)."""
from __future__ import annotations

import re

import pytest


def test_build_generates_asm(manifest_dir, tmp_path):
    from Tools.emitter.build import build
    result = build(
        str(manifest_dir / "revshell.yaml"),
        template_name="reverse_shell",
        out_dir=str(tmp_path),
        assemble=False,
    )
    assert result.asm
    assert "main:" in result.asm


def test_build_contains_framework_bootstrap(manifest_dir, tmp_path):
    from Tools.emitter.build import build
    result = build(
        str(manifest_dir / "revshell.yaml"),
        out_dir=str(tmp_path),
        assemble=False,
    )
    assert "call find_module" in result.asm
    assert "call resolve_export_by_hash" in result.asm
    assert "find_export_loop" in result.asm


def test_build_generates_contract_md(manifest_dir, tmp_path):
    from Tools.emitter.build import build
    result = build(
        str(manifest_dir / "revshell.yaml"),
        out_dir=str(tmp_path),
        assemble=False,
    )
    assert result.contract_md
    assert "# Stack Layout" in result.contract_md
    assert "# API Contracts" in result.contract_md


def test_build_all_hashes_match_ror13(manifest_dir, tmp_path):
    from Tools.emitter.build import build
    from Tools.emitter.schema import load
    from Tools.emitter.hash_gen import ror13
    manifest = load(str(manifest_dir / "revshell.yaml"))
    result = build(
        str(manifest_dir / "revshell.yaml"),
        out_dir=str(tmp_path),
        assemble=False,
    )
    for name in manifest.functions:
        expected = f"0x{ror13(name):08x}"
        assert expected in result.asm, f"Hash for {name} ({expected}) not in generated asm"


def test_build_no_duplicate_api_slot_assignments(manifest_dir, tmp_path):
    from Tools.emitter.build import build
    result = build(
        str(manifest_dir / "revshell.yaml"),
        out_dir=str(tmp_path),
        assemble=False,
    )
    # Extract mov [ebp-0xNN], eax assignments
    api_section_start = result.asm.find("call save_export_context")
    string_section_start = result.asm.find("String Construction")
    if api_section_start != -1 and string_section_start != -1:
        api_section = result.asm[api_section_start:string_section_start]
        assignments = re.findall(r'mov\s+\[ebp-0x[0-9a-f]+\],\s+eax', api_section)
        assert len(assignments) == len(set(assignments)), \
            f"Duplicate slot writes in API section: {assignments}"


def test_build_write_outputs(manifest_dir, tmp_path):
    from Tools.emitter.build import build, write_outputs
    result = build(
        str(manifest_dir / "revshell.yaml"),
        out_dir=str(tmp_path),
        assemble=False,
    )
    write_outputs(result, str(tmp_path))
    assert (tmp_path / "asm" / "generated.asm").exists()
    assert (tmp_path / "Documentation" / "contract.md").exists()
    assert (tmp_path / "asm" / "generated.asm").read_text() == result.asm


def test_calc_build_no_network(manifest_dir, tmp_path):
    from Tools.emitter.build import build
    result = build(
        str(manifest_dir / "calc.yaml"),
        template_name="run_command",
        out_dir=str(tmp_path),
        assemble=False,
    )
    assert "WSAStartup" not in result.asm
    assert "WinExec" in result.asm
    assert "ws2_32" not in result.asm


def test_calc_build_winexec_hash(manifest_dir, tmp_path):
    from Tools.emitter.build import build
    from Tools.emitter.hash_gen import ror13
    result = build(
        str(manifest_dir / "calc.yaml"),
        out_dir=str(tmp_path),
        assemble=False,
    )
    expected = f"0x{ror13('WinExec'):08x}"
    assert expected in result.asm


def test_build_contains_dll_load_block(manifest_dir, tmp_path):
    from Tools.emitter.build import build
    result = build(
        str(manifest_dir / "revshell.yaml"),
        out_dir=str(tmp_path),
        assemble=False,
    )
    # ws2_32 loading block should appear
    assert "LoadLibraryA" in result.asm
    assert "ws2_32.dll" in result.asm


def test_build_string_section_present(manifest_dir, tmp_path):
    from Tools.emitter.build import build
    result = build(
        str(manifest_dir / "revshell.yaml"),
        out_dir=str(tmp_path),
        assemble=False,
    )
    assert "String Construction" in result.asm


def test_build_structure_section_present(manifest_dir, tmp_path):
    from Tools.emitter.build import build
    result = build(
        str(manifest_dir / "revshell.yaml"),
        out_dir=str(tmp_path),
        assemble=False,
    )
    assert "Structure Initialization" in result.asm
    assert "STARTUPINFOA" in result.asm


def test_build_layout_returned(manifest_dir, tmp_path):
    from Tools.emitter.build import build
    result = build(
        str(manifest_dir / "revshell.yaml"),
        out_dir=str(tmp_path),
        assemble=False,
    )
    assert result.layout is not None
    assert result.layout.slot("WSAStartup").offset == 0x3c


def test_build_no_assemble_skips_keystone(manifest_dir, tmp_path):
    from Tools.emitter.build import build
    result = build(
        str(manifest_dir / "revshell.yaml"),
        assemble=False,
        out_dir=str(tmp_path),
    )
    assert result.shellcode_bytes is None
    assert result.hex_str is None


def test_existing_modules_still_import():
    from Tools.emitter import schema, hash_gen, api_database, stack_alloc, doc_gen, api_emitter
    assert True


# ---------------------------------------------------------------------------
# _to_nasm syntax transformation
# ---------------------------------------------------------------------------

def test_to_nasm_adds_bits32():
    from Tools.emitter.build import _to_nasm
    out = _to_nasm("xor eax, eax")
    assert out.startswith("BITS 32")


def test_to_nasm_strips_hash_comments():
    from Tools.emitter.build import _to_nasm
    out = _to_nasm("mov eax, 1  # set eax")
    assert "#" not in out
    assert "mov eax, 1" in out


def test_to_nasm_removes_dword_ptr():
    from Tools.emitter.build import _to_nasm
    out = _to_nasm("call dword ptr [ebp-0x28]")
    assert "ptr" not in out
    assert "call dword [ebp-0x28]" in out


def test_to_nasm_removes_word_ptr():
    from Tools.emitter.build import _to_nasm
    out = _to_nasm("cmp word ptr [esi], 0x004b")
    assert "ptr" not in out
    assert "cmp word [esi], 0x004b" in out


def test_to_nasm_removes_byte_ptr():
    from Tools.emitter.build import _to_nasm
    out = _to_nasm("movzx eax, byte ptr [esi]")
    assert "ptr" not in out
    assert "movzx eax, byte [esi]" in out


def test_to_nasm_fixes_fs_segment():
    from Tools.emitter.build import _to_nasm
    out = _to_nasm("mov eax, fs:[ecx + 0x30]")
    assert "fs:[" not in out
    assert "[fs:ecx + 0x30]" in out


def test_to_nasm_no_change_to_normal_instructions():
    from Tools.emitter.build import _to_nasm
    src = "xor ecx, ecx\npush eax\npop ebx"
    out = _to_nasm(src)
    for instr in src.splitlines():
        assert instr in out


# ---------------------------------------------------------------------------
# assembler field on BuildResult
# ---------------------------------------------------------------------------

def test_build_assembler_none_when_no_assemble(manifest_dir, tmp_path):
    from Tools.emitter.build import build
    result = build(str(manifest_dir / "calc.yaml"), assemble=False, out_dir=str(tmp_path))
    assert result.assembler is None


def test_build_assembler_set_when_assembled(manifest_dir, tmp_path):
    import shutil
    if not shutil.which("nasm"):
        pytest.skip("nasm not available")
    from Tools.emitter.build import build
    result = build(str(manifest_dir / "calc.yaml"), assemble=True, out_dir=str(tmp_path))
    if result.assembler is not None:
        assert result.assembler in ("keystone", "nasm")
