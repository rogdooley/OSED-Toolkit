import struct
import sys

import pytest

from Tools.rawlayout.payload_builder import (
    build_payload,
    format_layout_report_table,
    generate_external_bytes,
    register_computed_function,
)


def test_relationships_use_param_offset_not_magic_constants():
    spec = {
        "params": {"eip_offset": 40},
        "segments": [
            {"append": {"name": "head", "source": "bytes", "value": "HEAD"}},
            {"label": "after_head"},
            {"pad_to": {"name": "pad", "target": {"param": "eip_offset"}, "byte": "0x41"}},
            {
                "at": {
                    "name": "ret",
                    "offset": {"param": "eip_offset"},
                    "source": "int",
                    "value": "0x11223344",
                    "size": 4,
                    "endian": "little",
                }
            },
            {"pad_to": {"name": "after_ret", "target": {"add": [{"param": "eip_offset"}, 4]}}},
            {"append": {"name": "tail", "source": "bytes", "value": "TAIL"}},
        ],
    }

    result = build_payload(spec)
    eip_offset = spec["params"]["eip_offset"]
    assert result.payload[eip_offset : eip_offset + 4] == struct.pack("<I", 0x11223344)

    tail_segment = next(s for s in result.report.segments if s.name == "tail")
    assert tail_segment.start == eip_offset + 4
    assert result.report.labels["after_head"] == len(b"HEAD")
    assert result.report.overlaps == []


def test_overlap_rejected_by_default():
    spec = {
        "segments": [
            {"append": {"name": "a", "source": "bytes", "value": "AAAAAAAAAA"}},
            {
                "at": {
                    "name": "b",
                    "offset": 5,
                    "source": "bytes",
                    "value": "BBBB",
                }
            },
        ]
    }

    with pytest.raises(ValueError, match="overlap detected"):
        build_payload(spec)


def test_overlap_allowed_when_segment_opt_in():
    spec = {
        "segments": [
            {"append": {"name": "a", "source": "bytes", "value": "AAAAAAAAAA"}},
            {
                "at": {
                    "name": "b",
                    "offset": 5,
                    "source": "bytes",
                    "value": "BBBB",
                    "allow_overlap": True,
                }
            },
        ]
    }

    result = build_payload(spec)
    assert result.payload[5:9] == b"BBBB"
    assert len(result.report.overlaps) >= 1


def test_external_command_bytes_and_validation():
    spec = {
        "external_commands": {
            "emit": [
                sys.executable,
                "-c",
                "import sys; sys.stdout.buffer.write(b'XYZ')",
            ]
        },
        "external_validation": {"assert_len_max": 8},
        "constraints": {"assert_len_exact": 5},
        "segments": [
            {"append": {"name": "gen", "source": "external", "command_ref": "emit"}},
            {"append": {"name": "tail", "source": "bytes", "value": "12"}},
        ],
    }

    result = build_payload(spec)
    assert result.payload == b"XYZ12"


def test_external_generator_enforces_max_output_bytes():
    with pytest.raises(ValueError, match="exceeds max_output_bytes"):
        generate_external_bytes(
            [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'ABCDEFGHIJ')"],
            timeout_s=2.0,
            cwd=None,
            env=None,
            max_output_bytes=5,
        )


def test_final_constraints_support_param_expression():
    spec = {
        "params": {"max_len": 8},
        "constraints": {"assert_len_max": {"param": "max_len"}},
        "segments": [
            {"append": {"name": "x", "source": "bytes", "value": "ABCDEFGH"}},
        ],
    }

    result = build_payload(spec)
    assert result.payload == b"ABCDEFGH"


def test_computed_source_receives_build_context():
    seen: dict[str, object] = {}

    def capture(args: dict, ctx) -> bytes:
        seen["current_offset"] = ctx.current_offset
        seen["segment_offsets"] = dict(ctx.segment_offsets)
        seen["total_size_so_far"] = ctx.total_size_so_far
        return bytes([args["byte"]])

    register_computed_function("capture_ctx", capture, overwrite=True)

    spec = {
        "segments": [
            {"append": {"name": "pre", "source": "bytes", "value": "AB"}},
            {"label": "here"},
            {
                "append": {
                    "name": "computed",
                    "source": "computed",
                    "function": "capture_ctx",
                    "args": {"byte": 0x43},
                }
            },
        ]
    }

    result = build_payload(spec)
    assert result.payload == b"ABC"
    assert seen["current_offset"] == 2
    assert seen["total_size_so_far"] == 2
    assert seen["segment_offsets"]["pre"] == (0, 2)
    assert seen["segment_offsets"]["here"] == (2, 2)


def test_computed_source_back_compat_args_only_function():
    def only_args(args: dict) -> bytes:
        return args["text"].encode("ascii")

    register_computed_function("only_args", only_args, overwrite=True)
    spec = {
        "segments": [
            {
                "append": {
                    "name": "computed",
                    "source": "computed",
                    "function": "only_args",
                    "args": {"text": "OK"},
                }
            }
        ]
    }
    result = build_payload(spec)
    assert result.payload == b"OK"


def test_duplicate_label_fails():
    spec = {
        "segments": [
            {"label": "dup"},
            {"append": {"name": "x", "source": "bytes", "value": "A"}},
            {"label": "dup"},
        ]
    }
    with pytest.raises(ValueError, match="duplicate label"):
        build_payload(spec)


def test_assert_offset_failure():
    spec = {
        "segments": [
            {"append": {"name": "x", "source": "bytes", "value": "ABC"}},
            {"assert_offset": 4},
        ]
    }
    with pytest.raises(ValueError, match="assert_offset failed"):
        build_payload(spec)


def test_assert_max_size_failure():
    spec = {
        "segments": [
            {"append": {"name": "x", "source": "bytes", "value": "ABCDE"}},
            {"assert_max_size": 4},
        ]
    }
    with pytest.raises(ValueError, match="assert_max_size failed"):
        build_payload(spec)


def test_overlap_error_contains_segment_names_and_overlap_range():
    spec = {
        "segments": [
            {"append": {"name": "alpha", "source": "bytes", "value": "AAAAAAAAAA"}},
            {"at": {"name": "beta", "offset": 7, "source": "bytes", "value": "BBBB"}},
        ]
    }
    with pytest.raises(ValueError) as exc:
        build_payload(spec)
    msg = str(exc.value)
    assert "alpha" in msg
    assert "beta" in msg
    assert "[7, 10)" in msg


def test_layout_report_table_has_expected_columns():
    spec = {
        "segments": [
            {"append": {"name": "h", "source": "text", "value": "HI"}},
        ]
    }
    result = build_payload(spec)
    table = format_layout_report_table(result.report)
    assert "Segment" in table
    assert "Start" in table
    assert "End" in table
    assert "Size" in table
    assert "Total size: 2" in table
