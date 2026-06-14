from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from Exploits.windows_x86.build_cmd import emit_shiftor, emit_xor


def test_shiftor_reports_badchar_in_shift_immediate() -> None:
    result = emit_shiftor("calc.exe", badchars={0x08})
    assert 0x08 in result.badchars
    assert any("0x08" in warning for warning in result.warnings)


def test_xor_emitter_uses_requested_destination_register() -> None:
    result = emit_xor("calc.exe", dest="esi")
    assert "lea  edi, [encoded_esi]" in result.asm
    assert "mov  eax, [edi]" in result.asm
    assert "mov  [esi], eax" in result.asm
    assert "add  edi, 4" in result.asm
    assert "add  esi, 4" in result.asm
    assert "0xNN" not in result.asm


def test_xor_emitter_rejects_out_of_range_key_by_auto_selecting() -> None:
    result = emit_xor("calc.exe", key=0x100)
    assert result.clean
    assert any("out of range for a single byte" in warning for warning in result.warnings)
    assert "0xNN" not in result.asm
