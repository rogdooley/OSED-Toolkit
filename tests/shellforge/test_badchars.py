from shellforge.analysis.badchars import contains_badchars, find_badchars, parse_badchars


def test_parse_badchars() -> None:
    assert parse_badchars("00,0a,0D") == b"\x00\x0a\x0d"


def test_find_badchars() -> None:
    data = b"\x90\x00\x90\x0a\x41"
    assert find_badchars(data, b"\x00\x0a") == [1, 3]
    assert contains_badchars(data, b"\x0d") is False
