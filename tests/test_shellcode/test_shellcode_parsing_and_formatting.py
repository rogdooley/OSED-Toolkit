import unittest

from Tools.shellcode.analyze import analyze_shellcode
from Tools.shellcode.formatting import format_bytes
from Tools.shellcode.parsing import (
    ParseError,
    parse_c_array,
    parse_escaped_hex,
    parse_hex,
    parse_py_bytes_literal,
)


class TestShellcodeParsing(unittest.TestCase):
    def test_parse_hex(self):
        self.assertEqual(parse_hex("deadbeef"), b"\xde\xad\xbe\xef")
        self.assertEqual(parse_hex("de ad be ef"), b"\xde\xad\xbe\xef")
        self.assertEqual(parse_hex("0xdeadbeef"), b"\xde\xad\xbe\xef")

    def test_parse_hex_rejects_odd(self):
        with self.assertRaises(ParseError):
            parse_hex("abc")

    def test_parse_escaped_hex(self):
        self.assertEqual(parse_escaped_hex(r"\x90\x90\xcc"), b"\x90\x90\xcc")

    def test_parse_c_array(self):
        self.assertEqual(parse_c_array("{ 0x90, 0x90, 0xcc }"), b"\x90\x90\xcc")

    def test_parse_py_bytes_literal(self):
        self.assertEqual(parse_py_bytes_literal(r"b'\x90\x90\xcc'"), b"\x90\x90\xcc")


class TestShellcodeAnalyze(unittest.TestCase):
    def test_analyze_badchars_defaultish(self):
        rep = analyze_shellcode(b"\x90\x00\xcc", badchars=(0x00, 0x0A, 0x0D))
        self.assertEqual(rep.length, 3)
        self.assertEqual(rep.badchars, [0x00])


class TestShellcodeFormatting(unittest.TestCase):
    def test_format_hex(self):
        self.assertEqual(format_bytes(b"\xde\xad", fmt="hex"), "dead")

    def test_format_escaped(self):
        self.assertEqual(format_bytes(b"\xde\xad", fmt="escaped"), r"\xde\xad")

    def test_format_py_contains_var(self):
        out = format_bytes(b"\x90\xcc", fmt="py", var_name="sc")
        self.assertIn("sc = b", out)
        self.assertIn(r"\x90\xcc", out)

    def test_format_c_contains_array(self):
        out = format_bytes(b"\x90\xcc", fmt="c", var_name="sc")
        self.assertIn("unsigned char sc[]", out)
        self.assertIn("0x90", out)


if __name__ == "__main__":
    unittest.main()

