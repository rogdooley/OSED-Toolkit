from Tools.badchars.cli.generate_badchars import main, parse_exclusions


def test_default_is_pasteable_python_without_null(capsys):
    assert main([]) == 0
    output = capsys.readouterr().out.strip()
    assert output.startswith('badchars = b"\\x01\\x02')
    assert output.endswith('\\xfe\\xff"')
    assert "\\x00" not in output


def test_exclusions_accept_common_notation(capsys):
    assert main(["--exclude", r"0x00,\x0a 0d", "--format", "escaped"]) == 0
    output = capsys.readouterr().out.strip()
    assert "\\x00" not in output
    assert "\\x0a" not in output
    assert "\\x0d" not in output


def test_empty_exclusion_includes_every_byte(capsys):
    assert main(["--exclude", "", "--format", "hex"]) == 0
    output = capsys.readouterr().out.strip()
    assert len(output) == 512
    assert output.startswith("000102")
    assert output.endswith("fdfeff")


def test_parse_exclusions_deduplicates_bytes():
    assert parse_exclusions("00,0x00,ff") == (0x00, 0xFF)
