import unittest

from Tools.shellcode.shellcode_encoder import (
    ShellcodeEncodingError,
    contains_badchars,
    encode_xor,
    encode_xor_with_metadata,
)


class TestContainsBadchars(unittest.TestCase):
    def test_detects_badchars(self):
        self.assertTrue(contains_badchars(b"\x90\x00\xcc", b"\x00\x0a"))
        self.assertFalse(contains_badchars(b"\x90\xcc", b"\x00\x0a"))


class TestXorEncoder(unittest.TestCase):
    def test_encode_xor_returns_stub_plus_payload(self):
        payload = b"\x90\x90\xcc"
        encoded = encode_xor(payload, b"\x00\x0a\x0d")

        # Stub is compact and may vary by length-loader strategy (20-22 bytes).
        self.assertGreaterEqual(len(encoded), 20 + len(payload))

    def test_metadata_reports_selected_key(self):
        payload = b"\x90\x90\xcc"
        result = encode_xor_with_metadata(payload, b"\x00\x0a\x0d")

        self.assertTrue(1 <= result.metadata.key <= 0xFF)
        self.assertEqual(result.metadata.original_size, len(payload))
        self.assertEqual(result.metadata.encoded_size, len(result.payload))
        self.assertGreater(result.metadata.stub_size, 0)
        self.assertEqual(
            result.metadata.size_increase,
            result.metadata.encoded_size - result.metadata.original_size,
        )

    def test_raises_when_no_key_possible(self):
        # For 1-byte payload, encoded result can only be one byte for each key.
        # If we ban all possible encoded bytes, selection must fail.
        payload = b"\x00"
        badchars = bytes(range(256))

        with self.assertRaises(ShellcodeEncodingError):
            encode_xor(payload, badchars)

    def test_raises_on_empty_payload(self):
        with self.assertRaises(ShellcodeEncodingError):
            encode_xor(b"", b"\x00")


if __name__ == "__main__":
    unittest.main()
