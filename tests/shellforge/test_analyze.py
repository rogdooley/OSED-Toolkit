from __future__ import annotations

from shellforge.analysis.analyze import analyze_bytes, build_hash_cross_reference
from shellforge.hashes.ror13 import ror13_hash


def test_analyze_detects_requested_signatures() -> None:
    blob = (
        b"\x64\xa1\x30\x00\x00\x00"  # fs:[30]
        + (b"\x90" * 12)  # nop sled
        + b"w00tw00t"  # egg marker
        + b"\xaa\xfc\x0d\x7c"  # ror13 GetProcAddress
        + b"STRING_ONE\x00"
    )
    report = analyze_bytes(blob)
    assert report.detected_arch == "x86"
    assert report.size == len(blob)
    assert len(report.peb_walk_signatures) >= 1
    assert len(report.segment_access_signatures) >= 1
    assert len(report.nop_sleds) >= 1
    assert len(report.egg_markers) >= 1
    assert len(report.api_hash_constants) >= 1
    assert any("STRING_ONE" in item for item in report.printable_strings)
    assert report.strings_truncated is False
    assert any(item["name"] == "peb_walk" and item["matched"] for item in report.heuristics)


def test_analyze_arch_auto_prefers_x64_on_gs60_signature() -> None:
    blob = b"\x65\x48\x8b\x04\x25\x60\x00\x00\x00\xc3"
    report = analyze_bytes(blob, arch="auto")
    assert report.detected_arch == "x64"
    assert report.detection_confidence >= 0.6


def test_analyze_strings_cap_and_truncation() -> None:
    blob = b"AAAA\x00BBBB\x00CCCC\x00DDDD\x00"
    report = analyze_bytes(blob, max_strings=2)
    assert len(report.printable_strings) == 2
    assert report.strings_truncated is True


def test_analyze_max_hits_applies_per_heuristic() -> None:
    blob = b"\x90" * 80
    report = analyze_bytes(blob, max_hits=1)
    nop = next(item for item in report.heuristics if item["name"] == "nop_sled")
    assert nop["matched"] is True
    assert nop["total_hits"] >= 1
    assert len(nop["offsets"]) == 1


def test_analyze_heuristics_sorted_deterministically() -> None:
    blob = b"\x64\xa1\x30\x00\x00\x00" + (b"\x90" * 16) + b"w00tw00t"
    report = analyze_bytes(blob)
    heur = report.heuristics
    matched_prefix_len = 0
    for row in heur:
        if row["matched"]:
            matched_prefix_len += 1
        else:
            break
    assert all(row["matched"] for row in heur[:matched_prefix_len])
    assert all(not row["matched"] for row in heur[matched_prefix_len:])
    for i in range(1, len(heur)):
        a, b = heur[i - 1], heur[i]
        if a["matched"] == b["matched"] and a["confidence"] == b["confidence"]:
            assert str(a["name"]) <= str(b["name"])


def test_analyze_hash_cross_reference_matches_known_constant() -> None:
    symbol = "GetProcAddress"
    value = ror13_hash(symbol)
    blob = value.to_bytes(4, "little")
    xref = build_hash_cross_reference([symbol], ror13_hash, namespace="kernel32.dll")
    report = analyze_bytes(blob, hash_cross_reference=xref)
    assert len(report.api_hash_constants) >= 1
    assert len(report.api_hash_cross_references) == 1
    row = report.api_hash_cross_references[0]
    assert row["hash_value"] == value
    assert "kernel32.dll!GetProcAddress" in row["matches"]
