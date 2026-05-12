from __future__ import annotations

import importlib.util

from shellforge.cli import main


def test_trace_human_output_compact_table(tmp_path, capsys) -> None:
    if importlib.util.find_spec("unicorn") is None:
        return
    sample = tmp_path / "trace.bin"
    sample.write_bytes(b"\x90\xc3")
    code = main(["trace", "--arch", "x86", "--steps", "8", str(sample)])
    assert code == 0
    out = capsys.readouterr().out
    assert "arch=x86" in out
    assert "stopped_reason=" in out
    assert "IDX  ADDR" in out
    assert "INSTRUCTION" in out
    assert "ESP/RSP" in out


def test_trace_human_stack_watch_and_writes(tmp_path, capsys) -> None:
    if importlib.util.find_spec("unicorn") is None:
        return
    sample = tmp_path / "trace_write.bin"
    sample.write_bytes(b"\xc7\x04\x24\x41\x41\x41\x41\xc3")
    code = main(["trace", "--arch", "x86", "--steps", "8", "--stack-window", "2", "--watch", "eip,esp", str(sample)])
    assert code == 0
    out = capsys.readouterr().out
    assert "writes=" in out
    assert "WATCH eip=" in out
    assert "STACK" in out
    assert "WRITE 0x" in out


def test_trace_human_explain_peb_annotations(tmp_path, capsys) -> None:
    if importlib.util.find_spec("unicorn") is None:
        return
    sample = tmp_path / "trace_peb.bin"
    sample.write_bytes(b"\x64\xa1\x30\x00\x00\x00")
    code = main(["trace", "--arch", "x86", "--steps", "1", "--explain-peb", str(sample)])
    assert code == 0
    out = capsys.readouterr().out
    assert "accessing PEB" in out
