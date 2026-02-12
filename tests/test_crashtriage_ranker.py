from pathlib import Path

from Tools.crashtriage.parser import parse_dump
from Tools.crashtriage.ranker import rank_candidates
from Tools.crashtriage.recommend import build_recommendations


FIXTURES = Path(__file__).parent / "fixtures" / "crashtriage"


def _fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def test_x86_eip_is_top_ranked_high_confidence():
    parsed = parse_dump(_fixture("x86_windbg_eip_clean.txt"))
    candidates = rank_candidates(parsed, "x86")
    assert candidates[0].register == "EIP"
    assert candidates[0].confidence == "high"


def test_missing_eip_uses_exception_or_stack_candidates():
    parsed = parse_dump(_fixture("x86_no_eip_but_exception_value.txt"))
    candidates = rank_candidates(parsed, "x86")
    assert candidates[0].register in ("ESP", "EBP", None)


def test_recommendations_emit_normal_and_raw_variants():
    parsed = parse_dump(_fixture("x86_windbg_eip_clean.txt"))
    candidates = rank_candidates(parsed, "x86")
    recommendations, notes = build_recommendations(
        candidates,
        length=3000,
        arch="x86",
        endianness="little",
        all_candidates=False,
    )
    assert len(recommendations) >= 2
    assert any(not r.raw for r in recommendations)
    assert any(r.raw for r in recommendations)
    assert notes == []
