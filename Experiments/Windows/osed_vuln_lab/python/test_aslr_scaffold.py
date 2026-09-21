from __future__ import annotations

import unittest
from struct import pack

from aslr_scaffold import parse_leak_response
from exploit_scaffold import CONTROL_V2_RECORD, OSED_MAGIC, OP_LEAK, RECORD_QUERY


class AslrScaffoldTests(unittest.TestCase):
    def test_parse_leak_response_returns_pointer(self) -> None:
        response = pack(
            "<IHHIHHI",
            OSED_MAGIC,
            OP_LEAK,
            CONTROL_V2_RECORD,
            8,
            0,
            RECORD_QUERY,
            0x62501234,
        )
        self.assertEqual(parse_leak_response(response), 0x62501234)

    def test_parse_leak_response_rejects_wrong_control(self) -> None:
        response = pack(
            "<IHHIHHI",
            OSED_MAGIC,
            OP_LEAK,
            0,
            8,
            0,
            RECORD_QUERY,
            0x62501234,
        )
        with self.assertRaises(RuntimeError):
            parse_leak_response(response)


if __name__ == "__main__":
    unittest.main()
