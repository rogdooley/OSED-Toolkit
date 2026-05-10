from __future__ import annotations

from shellforge.cli import main


def test_disasm_human_output_table(tmp_path, capsys) -> None:
    sample = tmp_path / "code.bin"
    sample.write_bytes(b"\x90\xc3")
    code = main(["disasm", "--arch", "x86", "--base", "0x1000", str(sample)])
    assert code == 0
    out = capsys.readouterr().out
    assert "arch=x86" in out
    assert "entropy=" in out
    assert "printable_ratio=" in out
    assert "null_bytes=0" in out
    assert "address" in out
    assert "mnemonic" in out
    assert "0x00001000" in out
    assert "nop" in out
