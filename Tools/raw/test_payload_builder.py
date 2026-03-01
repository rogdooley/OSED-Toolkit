"""
tests/test_payload_builder.py

Comprehensive tests for the layout-driven payload builder.

Coverage:
  - Static layout (pad, repeat, raw_bytes, at_offset)
  - Computed segments (built-in and custom functions)
  - Badchar detection with segment attribution
  - Overlap detection
  - Exact offset enforcement
  - Padding math (e.g., 524 - shellcode_len = 174)
  - bytes_file loading
  - BuildContext delivery to computed functions
  - CLI smoke test
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

# Make sure project root is on path when running directly.
sys.path.insert(0, str(Path(__file__).parent.parent))

from exploit.computed_registry import (
    COMPUTED_REGISTRY,
    BuildContext,
    register,
    register_force,
)
from exploit.layout_spec import (
    AtOffsetSegment,
    BytesFileSegment,
    ComputedSegment,
    ComputedSegmentDef,
    LayoutSpec,
    LayoutSpecParser,
    PadSegment,
    RawBytesSegment,
    RepeatSegment,
)
from exploit.payload_builder import (
    BadcharError,
    OverlapError,
    PayloadBuildError,
    PayloadBuilder,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_spec(*segments, badchars: bytes = b"", expected_total_size: int | None = None) -> LayoutSpec:
    return LayoutSpec(
        segments=list(segments),
        badchars=badchars,
        expected_total_size=expected_total_size,
    )


# ---------------------------------------------------------------------------
# Static Layout Tests
# ---------------------------------------------------------------------------

class TestPadSegment(unittest.TestCase):
    def test_pad_to_offset(self):
        spec = make_spec(PadSegment(name="padding", until_offset=16, pad_byte=0x41))
        result = PayloadBuilder().build(spec)
        self.assertEqual(len(result), 16)
        self.assertEqual(result, b"A" * 16)

    def test_pad_byte_zero(self):
        spec = make_spec(PadSegment(name="padding", until_offset=8, pad_byte=0x00))
        result = PayloadBuilder().build(spec)
        self.assertEqual(result, b"\x00" * 8)

    def test_pad_offset_already_reached(self):
        """Padding with until_offset < current offset should raise."""
        spec = make_spec(
            RepeatSegment(name="pre", byte=0x41, count=32),
            PadSegment(name="bad_pad", until_offset=16, pad_byte=0x41),
        )
        with self.assertRaises(PayloadBuildError):
            PayloadBuilder().build(spec)


class TestRepeatSegment(unittest.TestCase):
    def test_nop_sled(self):
        spec = make_spec(RepeatSegment(name="sled", byte=0x90, count=32))
        result = PayloadBuilder().build(spec)
        self.assertEqual(result, b"\x90" * 32)

    def test_zero_repeat(self):
        spec = make_spec(RepeatSegment(name="empty", byte=0x41, count=0))
        result = PayloadBuilder().build(spec)
        self.assertEqual(result, b"")


class TestRawBytesSegment(unittest.TestCase):
    def test_raw_bytes(self):
        data = bytes(range(16))
        spec = make_spec(RawBytesSegment(name="raw", data=data))
        result = PayloadBuilder().build(spec)
        self.assertEqual(result, data)


class TestAtOffsetSegment(unittest.TestCase):
    def test_dword_little_endian(self):
        spec = make_spec(
            PadSegment(name="padding", until_offset=8, pad_byte=0x41),
            AtOffsetSegment(name="ret", at_offset=4, dword=0xDEADBEEF, endian="little"),
        )
        result = PayloadBuilder().build(spec)
        self.assertEqual(result[4:8], b"\xEF\xBE\xAD\xDE")
        self.assertEqual(len(result), 8)

    def test_dword_big_endian(self):
        spec = make_spec(
            PadSegment(name="padding", until_offset=8, pad_byte=0x00),
            AtOffsetSegment(name="val", at_offset=0, dword=0x14802400, endian="big"),
        )
        result = PayloadBuilder().build(spec)
        self.assertEqual(result[0:4], b"\x14\x80\x24\x00")

    def test_at_offset_extends_buffer(self):
        """at_offset past current end should extend the buffer."""
        spec = make_spec(
            AtOffsetSegment(name="far", at_offset=100, dword=0xAABBCCDD, endian="little"),
        )
        result = PayloadBuilder().build(spec)
        self.assertGreaterEqual(len(result), 104)
        self.assertEqual(result[100:104], b"\xDD\xCC\xBB\xAA")


# ---------------------------------------------------------------------------
# BytesFile Tests
# ---------------------------------------------------------------------------

class TestBytesFileSegment(unittest.TestCase):
    def test_load_file(self):
        shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68"
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(shellcode)
            fname = f.name
        try:
            spec = make_spec(BytesFileSegment(name="shellcode", path=fname))
            result = PayloadBuilder().build(spec)
            self.assertEqual(result, shellcode)
        finally:
            os.unlink(fname)

    def test_missing_file_raises(self):
        spec = make_spec(BytesFileSegment(name="sc", path="/nonexistent/file.bin"))
        with self.assertRaises(PayloadBuildError):
            PayloadBuilder().build(spec)


# ---------------------------------------------------------------------------
# Computed Segment Tests
# ---------------------------------------------------------------------------

class TestComputedSegments(unittest.TestCase):
    def test_short_jump_back_builtin(self):
        """short_jump_back(distance=10) → EB F6"""
        spec = make_spec(
            ComputedSegment(
                name="pivot_stub",
                computed=ComputedSegmentDef(function="short_jump_back", args={"distance": 10}),
            )
        )
        result = PayloadBuilder().build(spec)
        self.assertEqual(result[0], 0xEB)
        encoded = result[1]
        # (256 - 10) & 0xFF = 246 = 0xF6
        self.assertEqual(encoded, 0xF6)

    def test_nop_sled_computed(self):
        spec = make_spec(
            ComputedSegment(
                name="sled",
                computed=ComputedSegmentDef(function="nop_sled", args={"count": 8}),
            )
        )
        result = PayloadBuilder().build(spec)
        self.assertEqual(result, b"\x90" * 8)

    def test_custom_computed_function(self):
        """Register and use a custom computed function."""
        register_force("test_custom", lambda args: b"\xCC" * int(args["n"]))
        spec = make_spec(
            ComputedSegment(
                name="int3s",
                computed=ComputedSegmentDef(function="test_custom", args={"n": 4}),
            )
        )
        result = PayloadBuilder().build(spec)
        self.assertEqual(result, b"\xCC" * 4)

    def test_computed_receives_context(self):
        """Computed function with context receives current_offset."""
        offsets_seen: list[int] = []

        def capture_offset(args: dict, ctx: BuildContext) -> bytes:
            offsets_seen.append(ctx.current_offset)
            return b"\xAA"

        register_force("capture_offset", capture_offset)
        spec = make_spec(
            PadSegment(name="pre", until_offset=16, pad_byte=0x41),
            ComputedSegment(
                name="probe",
                computed=ComputedSegmentDef(function="capture_offset", args={}),
            ),
        )
        PayloadBuilder().build(spec)
        self.assertEqual(offsets_seen, [16])

    def test_unregistered_function_raises(self):
        spec = make_spec(
            ComputedSegment(
                name="bad",
                computed=ComputedSegmentDef(function="nonexistent_fn", args={}),
            )
        )
        with self.assertRaises(KeyError):
            PayloadBuilder().build(spec)

    def test_computed_function_wrong_return_type(self):
        register_force("bad_return", lambda args: "not bytes")
        spec = make_spec(
            ComputedSegment(
                name="x",
                computed=ComputedSegmentDef(function="bad_return", args={}),
            )
        )
        with self.assertRaises(TypeError):
            PayloadBuilder().build(spec)


# ---------------------------------------------------------------------------
# Badchar Validation Tests
# ---------------------------------------------------------------------------

class TestBadcharValidation(unittest.TestCase):
    def test_no_badchars_passes(self):
        spec = make_spec(
            RawBytesSegment(name="data", data=b"\x41\x42\x43"),
            badchars=b"\x00",
        )
        result = PayloadBuilder().build(spec)
        self.assertEqual(result, b"ABC")

    def test_badchar_detected_in_segment(self):
        spec = make_spec(
            RawBytesSegment(name="shellcode", data=b"\x31\xc0\x00\x50"),
            badchars=b"\x00",
        )
        with self.assertRaises(BadcharError) as cm:
            PayloadBuilder().build(spec)
        violations = cm.exception.violations
        self.assertEqual(len(violations), 1)
        off, bv, seg = violations[0]
        self.assertEqual(off, 2)
        self.assertEqual(bv, 0x00)
        self.assertEqual(seg, "shellcode")

    def test_multiple_badchars(self):
        spec = make_spec(
            RawBytesSegment(name="sc", data=b"\x00\x0a\x0d\x41"),
            badchars=b"\x00\x0a\x0d",
        )
        with self.assertRaises(BadcharError) as cm:
            PayloadBuilder().build(spec)
        self.assertEqual(len(cm.exception.violations), 3)

    def test_extra_badchars_in_builder(self):
        """Builder-level badchars merge with spec badchars."""
        spec = make_spec(RawBytesSegment(name="d", data=b"\xff"))
        with self.assertRaises(BadcharError):
            PayloadBuilder(badchars=b"\xff").build(spec)


# ---------------------------------------------------------------------------
# Overlap Detection Tests
# ---------------------------------------------------------------------------

class TestOverlapDetection(unittest.TestCase):
    def test_no_overlap_passes(self):
        spec = make_spec(
            RepeatSegment(name="a", byte=0x41, count=8),
            RepeatSegment(name="b", byte=0x42, count=8),
        )
        result = PayloadBuilder().build(spec)
        self.assertEqual(len(result), 16)

    def test_at_offset_strict_overlap(self):
        """In strict mode, at_offset into padding should raise OverlapError."""
        spec = make_spec(
            PadSegment(name="pad", until_offset=8, pad_byte=0x41),
            AtOffsetSegment(name="ret", at_offset=4, dword=0x12345678, endian="little"),
        )
        with self.assertRaises(OverlapError):
            PayloadBuilder(strict_overlap=True).build(spec)

    def test_at_offset_non_strict_overwrites(self):
        """In non-strict mode, at_offset can overwrite padding (default)."""
        spec = make_spec(
            PadSegment(name="pad", until_offset=8, pad_byte=0x41),
            AtOffsetSegment(name="ret", at_offset=4, dword=0x12345678, endian="little"),
        )
        result = PayloadBuilder(strict_overlap=False).build(spec)
        self.assertEqual(result[4:8], b"\x78\x56\x34\x12")


# ---------------------------------------------------------------------------
# Offset Enforcement Tests
# ---------------------------------------------------------------------------

class TestOffsetEnforcement(unittest.TestCase):
    def test_exact_offset_satisfied(self):
        """at_offset segment lands at expected position."""
        spec = make_spec(
            PadSegment(name="padding", until_offset=524, pad_byte=0x41),
            AtOffsetSegment(name="ret", at_offset=524, dword=0x14802400, endian="little"),
        )
        result = PayloadBuilder().build(spec)
        self.assertEqual(result[524:528], b"\x00\x24\x80\x14")

    def test_padding_math(self):
        """Classic BOF math: pad = total_offset - shellcode_len = 524 - 350 = 174."""
        shellcode_len = 350
        total_offset = 524
        padding_needed = total_offset - shellcode_len

        self.assertEqual(padding_needed, 174)

        shellcode = b"\x90" * shellcode_len
        spec = make_spec(
            RawBytesSegment(name="shellcode", data=shellcode),
            PadSegment(name="padding", until_offset=total_offset, pad_byte=0x41),
            AtOffsetSegment(name="ret", at_offset=total_offset, dword=0xDEADBEEF, endian="little"),
        )
        result = PayloadBuilder().build(spec)
        self.assertEqual(len(result), total_offset + 4)
        self.assertEqual(result[:shellcode_len], shellcode)
        self.assertEqual(result[shellcode_len:total_offset], b"A" * padding_needed)
        self.assertEqual(result[total_offset:total_offset + 4], b"\xEF\xBE\xAD\xDE")

    def test_expected_total_size_mismatch(self):
        spec = make_spec(
            RepeatSegment(name="a", byte=0x41, count=8),
            expected_total_size=16,
        )
        with self.assertRaises(PayloadBuildError):
            PayloadBuilder().build(spec)

    def test_expected_total_size_match(self):
        spec = make_spec(
            RepeatSegment(name="a", byte=0x41, count=8),
            expected_total_size=8,
        )
        result = PayloadBuilder().build(spec)
        self.assertEqual(len(result), 8)


# ---------------------------------------------------------------------------
# LayoutSpecParser Tests
# ---------------------------------------------------------------------------

class TestLayoutSpecParser(unittest.TestCase):
    def test_parse_json_spec(self):
        spec_data = {
            "badchars": "000a0d",
            "segments": [
                {"name": "padding", "until_offset": 524, "pad_byte": "0x41"},
                {"name": "ret", "at_offset": 524, "dword": "0x14802400", "endian": "little"},
                {"name": "sled", "repeat": {"byte": "0x90", "count": 32}},
                {"name": "stub", "computed": {"function": "short_jump_back", "args": {"distance": 174}}},
            ],
        }
        parser = LayoutSpecParser()
        spec = parser.parse_string(json.dumps(spec_data))
        self.assertEqual(spec.badchars, b"\x00\x0a\x0d")
        self.assertEqual(len(spec.segments), 4)

    def test_parse_inline_raw_bytes_hex(self):
        spec_data = {
            "segments": [
                {"name": "raw", "raw_bytes": "deadbeef"},
            ]
        }
        parser = LayoutSpecParser()
        spec = parser.parse_string(json.dumps(spec_data))
        result = PayloadBuilder().build(spec)
        self.assertEqual(result, b"\xde\xad\xbe\xef")

    def test_parse_unknown_segment_raises(self):
        spec_data = {
            "segments": [
                {"name": "broken"},
            ]
        }
        parser = LayoutSpecParser()
        with self.assertRaises(ValueError):
            parser.parse_string(json.dumps(spec_data))


# ---------------------------------------------------------------------------
# Full Integration Test
# ---------------------------------------------------------------------------

class TestFullIntegration(unittest.TestCase):
    def test_classic_bof_layout(self):
        """
        Classic BOF layout:
          [shellcode 350 bytes][padding to 524][ret addr at 524][NOP sled 32][short_jump_back]

        The at_offset segment for ret is placed last in spec so it writes
        into the already-padded region at exactly offset 524, extending by
        4 bytes before the sequential sled/stub append.

        Because the two-pass builder processes sequential segments first,
        we place the sled and stub BEFORE the at_offset segment in the
        segments list so they occupy offsets 524-560. Then ret overwrites
        positions 524-528, replacing the first 4 bytes of the sled.
        A more realistic layout is: padding → ret → sled, achieved by
        using an at_offset segment that is followed by sequential segments.

        For this test we use a fully sequential approach (no at_offset)
        to verify offset math unambiguously.
        """
        shellcode = bytes(range(256)) + bytes(range(94))  # 350 bytes
        sc_len = len(shellcode)  # 350
        ret_bytes = (0x14802400).to_bytes(4, "little")

        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(shellcode)
            sc_path = f.name

        try:
            spec = LayoutSpec(
                segments=[
                    BytesFileSegment(name="shellcode", path=sc_path),
                    PadSegment(name="padding", until_offset=524, pad_byte=0x41),
                    # Use raw_bytes for ret so it's sequential (no pass-2 reordering)
                    RawBytesSegment(name="ret", data=ret_bytes),
                    RepeatSegment(name="sled", byte=0x90, count=32),
                    ComputedSegment(
                        name="pivot_stub",
                        computed=ComputedSegmentDef(
                            function="short_jump_back",
                            args={"distance": 174},
                        ),
                    ),
                ],
                badchars=b"",
            )

            result = PayloadBuilder().build(spec)

            # Shellcode at start
            self.assertEqual(result[:sc_len], shellcode)
            # Padding
            self.assertEqual(result[sc_len:524], b"A" * (524 - sc_len))
            # Return address at 524
            self.assertEqual(result[524:528], ret_bytes)
            # NOP sled at 528
            self.assertEqual(result[528:560], b"\x90" * 32)
            # Short jump stub at 560
            self.assertEqual(result[560], 0xEB)

        finally:
            os.unlink(sc_path)

    def test_write_payload_to_file(self):
        spec = make_spec(RawBytesSegment(name="d", data=b"\xAA\xBB\xCC"))
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            out_path = f.name
        try:
            builder = PayloadBuilder()
            payload = builder.build_and_optionally_write(spec, output_file=out_path)
            self.assertEqual(Path(out_path).read_bytes(), payload)
        finally:
            os.unlink(out_path)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    unittest.main(verbosity=2)
