from __future__ import annotations

from shellforge.analysis.disasm import disassemble_bytes


def test_disassemble_x86_with_base() -> None:
    result = disassemble_bytes(b"\x90\xc3", arch="x86", base=0x1000)
    assert result.arch == "x86"
    assert result.base == 0x1000
    assert len(result.instructions) == 2
    assert result.instructions[0].address == 0x1000
    assert result.instructions[0].mnemonic == "nop"
    assert result.instructions[1].mnemonic == "ret"
    assert result.metadata.size == 2
    assert result.metadata.null_byte_count == 0


def test_disassemble_x64_with_null_metadata() -> None:
    result = disassemble_bytes(b"\x48\x31\xc0\xc3\x00", arch="x64", base=0x2000)
    assert result.arch == "x64"
    assert result.instructions[0].address == 0x2000
    assert result.metadata.size == 5
    assert result.metadata.null_byte_count == 1
    assert 0.0 <= result.metadata.printable_ratio <= 1.0
