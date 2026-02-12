from pathlib import Path

from Tools.crashtriage.parser import parse_dump
from Tools.crashtriage.ranker import infer_arch


FIXTURES = Path(__file__).parent / "fixtures" / "crashtriage"


def _fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def test_parse_x86_windbg_eip_clean():
    parsed = parse_dump(_fixture("x86_windbg_eip_clean.txt"))
    reg_names = [r.name for r in parsed.registers]
    assert "EIP" in reg_names
    assert parsed.exception in ("c0000005", "access violation")


def test_parse_0x_prefixed_values_are_normalized():
    parsed = parse_dump(_fixture("x86_windbg_eip_0xprefix.txt"))
    eip = [r for r in parsed.registers if r.name == "EIP"][0]
    assert eip.value_hex == "42306142"


def test_infer_x64_when_rip_present():
    parsed = parse_dump(_fixture("x64_rip_clean.txt"))
    assert infer_arch(parsed, "auto") == "x64"


def test_infer_respects_forced_arch():
    parsed = parse_dump(_fixture("x64_rip_clean.txt"))
    assert infer_arch(parsed, "x86") == "x86"
