from __future__ import annotations

from shellforge.cli import main


def test_analyze_human_output_compact_report(tmp_path, capsys) -> None:
    sample = tmp_path / "analyze.bin"
    sample.write_bytes(
        b"\x64\xa1\x30\x00\x00\x00" + (b"\x90" * 10) + b"w00tw00t" + b"\xaa\xfc\x0d\x7c" + b"HELLO\x00"
    )
    code = main(["analyze", str(sample)])
    assert code == 0
    out = capsys.readouterr().out
    assert "arch=x86" in out
    assert "confidence=" in out
    assert "size=" in out
    assert "entropy=" in out
    assert "printable_ratio=" in out
    assert "null_bytes=" in out
    assert "hits:" in out
    assert "window=64" in out


def test_analyze_summary_only_human(tmp_path, capsys) -> None:
    sample = tmp_path / "analyze_summary.bin"
    sample.write_bytes(b"\x90" * 32 + b"\x00")
    code = main(["analyze", "--summary-only", str(sample)])
    assert code == 0
    out = capsys.readouterr().out
    assert "heuristic_hits=" in out
    assert "likely_decoder=" in out
