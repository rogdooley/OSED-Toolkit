from __future__ import annotations

import pytest

pytest.importorskip("unicorn")

from shellforge.analysis.trace import trace_bytes
from shellforge.contracts.errors import ShellforgeError


def test_trace_detects_call_push_pop_ret_jmp_flow() -> None:
    blob = (
        b"\x68\x01\x00\x00\x00"  # push 1
        b"\xE8\x05\x00\x00\x00"  # call 0x100f
        b"\x83\xC4\x04"  # add esp, 4 (cdecl cleanup)
        b"\xEB\x01"  # jmp +1
        b"\xC3"  # callee: ret
        b"\x90"  # end: nop
    )
    result = trace_bytes(blob, arch="x86", base=0x1000, steps=16)
    mnemonics = [row.mnemonic for row in result.trace]
    assert "call" in mnemonics
    assert "ret" in mnemonics
    assert "push" in mnemonics
    assert "jmp" in mnemonics
    assert result.arch == "x86"
    assert result.steps_executed > 0


def test_trace_cdecl_vs_stdcall_stack_cleanup_difference() -> None:
    cdecl_blob = (
        b"\x68\x01\x00\x00\x00"  # push 1
        b"\xE8\x05\x00\x00\x00"  # call 0x100f
        b"\x83\xC4\x04"  # add esp, 4 (caller cleanup)
        b"\xEB\x01"
        b"\xC3"  # ret
        b"\x90"
    )
    stdcall_blob = (
        b"\x68\x01\x00\x00\x00"  # push 1
        b"\xE8\x02\x00\x00\x00"  # call 0x100c
        b"\xEB\x03"
        b"\xC2\x04\x00"  # ret 4 (callee cleanup)
        b"\x90"
    )

    cdecl = trace_bytes(cdecl_blob, arch="x86", base=0x1000, steps=16)
    stdcall = trace_bytes(stdcall_blob, arch="x86", base=0x1000, steps=16)

    cdecl_add = next(row for row in cdecl.trace if row.mnemonic == "add")
    stdcall_ret = next(row for row in stdcall.trace if row.mnemonic == "ret")
    assert cdecl_add.stack_delta == 4
    assert stdcall_ret.stack_delta == 8


def test_trace_is_deterministic_for_same_input() -> None:
    blob = b"\x90\x90\xC3"
    first = trace_bytes(blob, arch="x86", base=0x2000, steps=8)
    second = trace_bytes(blob, arch="x86", base=0x2000, steps=8)
    assert first == second


def test_trace_stops_on_max_steps() -> None:
    blob = b"\x90\x90\x90\x90"
    result = trace_bytes(blob, arch="x86", base=0x3000, steps=2)
    assert result.steps_requested == 2
    assert result.steps_executed == 2
    assert result.stopped_reason == "max_steps_reached"


def test_trace_stops_on_unmapped_memory() -> None:
    blob = b"\xc3"  # ret -> pops deterministic stack value and leaves mapped area
    result = trace_bytes(blob, arch="x86", base=0x4000, steps=8)
    assert result.steps_executed >= 1
    assert result.stopped_reason in {"ret_unmapped_target", "unmapped_memory"}


def test_trace_rejects_steps_above_hard_limit() -> None:
    with pytest.raises(ShellforgeError) as exc_info:
        trace_bytes(b"\x90", arch="x86", base=0x1000, steps=10001)
    assert "hard maximum" in str(exc_info.value)


def test_trace_register_diff_contains_only_changed_registers() -> None:
    result = trace_bytes(b"\x90", arch="x86", base=0x5000, steps=1)
    assert result.trace
    row = result.trace[0]
    assert "eip" in row.register_diff
    assert "eax" not in row.register_diff
    assert "esp" not in row.register_diff


def test_trace_x64_stack_is_16_byte_aligned() -> None:
    result = trace_bytes(b"\x90", arch="x64", base=0x6000, steps=1)
    assert result.trace
    assert result.trace[0].stack_pointer_before % 16 == 0


def test_trace_collects_writes_and_summary() -> None:
    # mov dword ptr [esp], 0x41414141 ; ret
    blob = b"\xc7\x04\x24\x41\x41\x41\x41\xc3"
    result = trace_bytes(blob, arch="x86", base=0x7000, steps=4)
    assert result.write_summary["total_writes"] >= 1
    assert result.write_summary["by_class"]["stack"] >= 1
    writes = [w for row in result.trace for w in row.writes]
    assert writes
    assert writes[0]["classification"] == "stack"


def test_trace_detects_self_modifying_blob_write() -> None:
    # c6 05 00 80 00 00 90 -> mov byte ptr [0x8000], 0x90
    blob = b"\xc6\x05\x00\x80\x00\x00\x90"
    result = trace_bytes(blob, arch="x86", base=0x8000, steps=1)
    writes = [w for row in result.trace for w in row.writes]
    assert writes
    assert any(w["self_modifying"] for w in writes)
    assert result.write_summary["self_modifying_writes"] >= 1


def test_trace_stack_window_and_watch_projection() -> None:
    result = trace_bytes(b"\x90", arch="x86", base=0x9000, steps=1, stack_window_slots=2, watch_registers=["eip", "esp"])
    row = result.trace[0]
    assert len(row.stack_window) == 2
    assert "eip" in row.watched_registers
    assert "esp" in row.watched_registers


def test_trace_explain_peb_x86_fs30_annotation() -> None:
    # mov eax, fs:[0x30]
    blob = b"\x64\xa1\x30\x00\x00\x00"
    result = trace_bytes(blob, arch="x86", base=0xA000, steps=1, explain_peb=True)
    assert result.trace
    assert "accessing PEB" in result.trace[0].annotations


def test_trace_explain_peb_x64_gs60_annotation() -> None:
    # mov rax, gs:[0x60]
    blob = b"\x65\x48\x8b\x04\x25\x60\x00\x00\x00"
    result = trace_bytes(blob, arch="x64", base=0xB000, steps=1, explain_peb=True)
    assert result.trace
    assert "accessing PEB" in result.trace[0].annotations


def test_trace_explain_peb_loader_traversal_annotations() -> None:
    # lea eax,[eax+0xc]; lea esi,[eax+0x1c]; lea edi,[eax+0x14]
    blob = b"\x8d\x40\x0c\x8d\x70\x1c\x8d\x78\x14"
    result = trace_bytes(blob, arch="x86", base=0xC000, steps=3, explain_peb=True)
    annotations = [note for row in result.trace for note in row.annotations]
    assert "accessing PEB_LDR_DATA" in annotations
    assert any("walking loader list" in item for item in annotations)
