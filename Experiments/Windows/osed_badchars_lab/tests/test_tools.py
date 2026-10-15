import importlib.util
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]/"tools"
def _load(name):
 s=importlib.util.spec_from_file_location(name,ROOT/f"{name}.py");m=importlib.util.module_from_spec(s);assert s.loader;s.loader.exec_module(m);return m
def test_bytearray_and_comparison_are_observational():
 b=_load("bytearray"); c=_load("compare_bytes")
 assert b.build_bytearray(0,3,{1},2)==b"\x00\x02\x03\x00\x02\x03"
 report=c.compare_bytes(b"\x01\x02\x03",b"\x01\x04")
 assert report.truncation_at==2 and report.mismatches==[(1,2,4)]


def test_file_generator_preserves_candidate_and_declares_length():
 g=_load("generate_file")
 candidate=b"\x00\x41\xff"
 record=g.build_record("file03",candidate)
 assert record[:4]==b"BCF3"
 assert record[6:8]==len(candidate).to_bytes(2,"little")
 assert record[8:]==candidate
