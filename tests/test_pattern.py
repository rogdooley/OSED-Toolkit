from Tools.pattern.config import PatternConfig
from Tools.pattern.generator import PatternGenerator
from Tools.pattern.offset import OffsetResolver


def test_pattern_length():
    cfg = PatternConfig()
    gen = PatternGenerator(cfg)

    pattern = gen.create(100)

    assert len(pattern) == 100


def test_pattern_deterministic():
    cfg = PatternConfig()
    gen = PatternGenerator(cfg)

    p1 = gen.create(200)
    p2 = gen.create(200)

    assert p1 == p2


def test_offset_from_hex():
    cfg = PatternConfig()
    resolver = OffsetResolver(cfg)

    offset = resolver.find_offset(
        length=800,
        query="42306142",
    )

    assert offset == 780


def test_offset_from_int():
    cfg = PatternConfig()
    resolver = OffsetResolver(cfg)

    offset = resolver.find_offset(
        length=800,
        query=0x42306142,
    )

    assert offset == 780


def test_offset_raw_bytes():
    cfg = PatternConfig()
    resolver = OffsetResolver(cfg)

    offset = resolver.find_offset(
        length=800,
        query=b"B0aB",
        raw=True,
    )

    assert offset == 780


def test_offset_not_found():
    cfg = PatternConfig()
    resolver = OffsetResolver(cfg)

    offset = resolver.find_offset(
        length=800,
        query="deadbeef",
    )

    assert offset is None
