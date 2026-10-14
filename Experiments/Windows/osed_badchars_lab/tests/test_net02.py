from __future__ import annotations
from pathlib import Path
LAB_ROOT=Path(__file__).resolve().parents[1]
def test_net02_keeps_candidate_in_heap_structure_and_shared_processor():
    source=(LAB_ROOT/"challenges/net02/net02.c").read_text()
    assert "HeapAlloc" in source and "candidate" in source
    assert "net02_process_candidate" in source
    assert "STAGE_INITIAL_INPUT" in source and "STAGE_FINAL_DESTINATION" in source
