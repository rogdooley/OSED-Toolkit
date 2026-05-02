from shellforge.output.c_array import format_c_array
from shellforge.output.hex_dump import format_hex_dump
from shellforge.output.python_bytes import format_python_bytes
from shellforge.output.raw import format_raw


def test_raw_formatter() -> None:
    data = b"\x41\x42\x43"
    assert format_raw(data) == data


def test_python_formatter() -> None:
    rendered = format_python_bytes(b"\x41\x42")
    assert "payload = (" in rendered
    assert "\\x41\\x42" in rendered


def test_c_array_formatter() -> None:
    rendered = format_c_array(b"\x41\x42")
    assert "unsigned char payload[]" in rendered
    assert "0x41, 0x42" in rendered


def test_hex_dump_formatter() -> None:
    rendered = format_hex_dump(b"\x41\x00")
    assert "00000000" in rendered
    assert "41 00" in rendered
