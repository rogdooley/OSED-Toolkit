from Tools.badchars.badchars import BadCharAnalyzer


def test_no_badchars_exact_match():
    analyzer = BadCharAnalyzer(exclude=())

    expected = bytes([0x01, 0x02, 0x03, 0x04])
    observed = bytes([0x01, 0x02, 0x03, 0x04])

    result = analyzer.analyze(expected, observed)

    assert result.badchars == []
    assert result.transformed == {}


def test_missing_byte_detected():
    analyzer = BadCharAnalyzer(exclude=())

    expected = bytes([0x01, 0x02, 0x03, 0x04])
    observed = bytes([0x01, 0x02, 0x04])

    result = analyzer.analyze(expected, observed)

    assert result.badchars == [0x03]
    assert result.transformed == {}


def test_transformed_byte_detected():
    analyzer = BadCharAnalyzer(exclude=())

    expected = bytes([0x01, 0x02, 0x03, 0x04])
    observed = bytes([0x01, 0x02, 0x20, 0x04])

    result = analyzer.analyze(expected, observed)

    assert result.badchars == [0x03]
    assert result.transformed == {0x03: 0x20}


def test_multiple_missing_bytes():
    analyzer = BadCharAnalyzer(exclude=())

    expected = bytes([0x01, 0x02, 0x03, 0x04, 0x05])
    observed = bytes([0x01, 0x05])

    result = analyzer.analyze(expected, observed)

    assert result.badchars == [0x02, 0x03, 0x04]
    assert result.transformed == {}


def test_observed_truncated_marks_remaining_as_bad():
    analyzer = BadCharAnalyzer(exclude=())

    expected = bytes([0x01, 0x02, 0x03, 0x04])
    observed = bytes([0x01, 0x02])

    result = analyzer.analyze(expected, observed)

    assert result.badchars == [0x03, 0x04]
    assert result.transformed == {}


def test_excluded_bytes_not_generated_but_detectable():
    analyzer = BadCharAnalyzer(exclude=(0x00,))

    expected = bytes([0x01, 0x02, 0x00, 0x03])
    observed = bytes([0x01, 0x02, 0x03])

    result = analyzer.analyze(expected, observed)

    assert result.badchars == [0x00]
    assert result.transformed == {}


def test_multiple_transformations():
    analyzer = BadCharAnalyzer(exclude=())

    expected = bytes([0x01, 0x02, 0x03, 0x04])
    observed = bytes([0x01, 0x20, 0x30, 0x04])

    result = analyzer.analyze(expected, observed)

    assert result.badchars == [0x02, 0x03]
    assert result.transformed == {0x02: 0x20, 0x03: 0x30}
