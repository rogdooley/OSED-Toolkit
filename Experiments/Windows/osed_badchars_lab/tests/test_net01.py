from __future__ import annotations

import importlib.util
from pathlib import Path


LAB_ROOT = Path(__file__).resolve().parents[1]


def _sender():
    spec = importlib.util.spec_from_file_location("send_tcp", LAB_ROOT / "tools" / "send_tcp.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_net01_probe_and_overflow_context_preserve_candidate_after_mode_prefix() -> None:
    """Changing candidate placement must not alter the candidate bytes on wire."""
    sender = _sender()
    candidate = b"\x01\x02\x00\x03"
    probe = sender.build_payload("net01", "probe", candidate)
    overflow = sender.build_payload("net01", "overflow-context", candidate)
    assert probe.candidate_offset != overflow.candidate_offset
    assert probe.packet[probe.candidate_offset : probe.candidate_offset + len(candidate)] == candidate
    assert overflow.packet[overflow.candidate_offset : overflow.candidate_offset + len(candidate)] == candidate
    assert probe.packet[:4] == overflow.packet[:4] == b"BCN1"


def test_net01_source_keeps_probe_and_overflow_modes_on_one_processing_function() -> None:
    """Splitting transformations by mode would make observations non-transferable."""
    source = (LAB_ROOT / "challenges" / "net01" / "net01.c").read_text(encoding="utf-8")
    assert "net01_process_candidate" in source
    assert "stage_trace_capture(STAGE_INITIAL_INPUT" in source
    assert "stage_trace_capture(STAGE_FINAL_DESTINATION" in source
