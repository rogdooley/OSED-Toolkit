"""Private deterministic oracles; student packaging never copies tests/."""

from instructor_models import file01_stages, file02_stages, file03_stages, net02_stages, net03_stages


def test_net02_escape_and_quote_states_are_deterministic() -> None:
    first = net02_stages(b'a;"b;c"\\d')
    assert first == net02_stages(b'a;"b;c"\\d')
    assert first["initial"] == b'a;"b;c"\\d'
    assert first["post_transform"] != first["initial"]


def test_net03_record_boundaries_change_only_the_parser_stage() -> None:
    stages = net03_stages(b"\x02AB\x00\x02CD")
    assert stages["initial"] == b"\x02AB\x00\x02CD"
    assert stages["pre_transform"] == b"ABCD"
    assert stages["post_transform"] != stages["pre_transform"]


def test_file_models_cover_text_binary_chunk_and_boundary_cases() -> None:
    assert file01_stages(b"\x01\x03abc\x02\x02\x1aX")["pre_transform"] == b"abc\x1aX"
    assert file02_stages(b"\x02AB\x01C")["post_transform"] != b"ABC"
    within = file03_stages(b"\x01\x03A\\B")
    across = file03_stages(b"\x01\x02A\\\x01\x01B")
    assert within["post_transform"] != across["post_transform"]


def test_models_reject_truncated_records() -> None:
    for model in (net03_stages, file01_stages, file02_stages, file03_stages):
        try:
            model(b"\x04AB")
        except ValueError:
            pass
        else:
            raise AssertionError(f"{model.__name__} accepted a truncated record")
