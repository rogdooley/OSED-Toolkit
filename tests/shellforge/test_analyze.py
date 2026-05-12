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
    assert len(report.architecture_fingerprints) >= 1
    assert len(report.segment_access_signatures) >= 1
    assert len(report.nop_sleds) >= 1
    assert len(report.egg_markers) >= 1
    assert len(report.api_hash_constants) >= 1
    assert isinstance(report.suspicious_entropy_windows, list)
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


def test_analyze_detects_xor_additive_and_api_hash_loops() -> None:
    blob = (
        b"\x31\xc9"  # xor ecx, ecx
        b"\x31\xc0"  # xor eax, eax
        b"\x80\x36\xaa"  # xor byte ptr [esi], 0xaa
        b"\x46"  # inc esi
        b"\xe2\xfb"  # loop back
        b"\x80\x06\x01"  # add byte ptr [esi], 1
        b"\x46"  # inc esi
        b"\x49"  # dec ecx
        b"\x75\xf9"  # jnz back
        b"\xac"  # lodsb
        b"\xc1\xc8\x0d"  # ror eax, 0xd
        b"\x01\xc8"  # add eax, ecx
        b"\x75\xf9"  # jnz back
    )
    report = analyze_bytes(blob, arch="x86")
    assert len(report.xor_decoder_loop_signatures) >= 1
    assert len(report.additive_decoder_loop_signatures) >= 1
    assert len(report.api_hash_loop_signatures) >= 1


def test_analyze_flags_suspicious_entropy_windows_and_resolver_stub() -> None:
    high_entropy = bytes(range(256)) * 2
    resolver = b"\x64\xa1\x30\x00\x00\x00" + b"\xaa\xfc\x0d\x7c"
    blob = resolver + high_entropy
    report = analyze_bytes(blob, arch="x86", window=64, step=16)
    assert len(report.suspicious_entropy_windows) >= 1
    assert len(report.likely_resolver_stubs) >= 1
