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
