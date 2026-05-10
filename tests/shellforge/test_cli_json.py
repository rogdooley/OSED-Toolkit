from __future__ import annotations

import json
from datetime import datetime
import re

from shellforge.cli import main
from shellforge.hashes.ror13 import ror13_hash
from tests.shellforge.pe_fixture import (
    build_minimal_pe32_plus_with_export,
    build_minimal_pe32_with_export,
    build_minimal_pe32_with_imports,
)


def _load_json_from_stdout(capsys) -> dict[str, object]:
    out = capsys.readouterr().out.strip()
    return json.loads(out)


def _assert_common_json_fields(payload: dict[str, object]) -> None:
    assert payload["schema_version"] == 1
    assert payload["tool_version"] == "0.1.0"
    assert isinstance(payload["generated_at"], str)
    assert isinstance(payload["request_id"], str)
    assert re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
        payload["request_id"],
    )
    datetime.fromisoformat(payload["generated_at"].replace("Z", "+00:00"))


def _assert_success_envelope_shape(payload: dict[str, object]) -> None:
    _assert_common_json_fields(payload)
    assert payload["ok"] is True
    assert set(payload.keys()) == {
        "schema_version",
        "tool_version",
        "generated_at",
        "request_id",
        "command",
        "ok",
        "result",
    }


def _assert_error_envelope_shape(payload: dict[str, object]) -> None:
    _assert_common_json_fields(payload)
    assert payload["ok"] is False
    assert set(payload.keys()) == {
        "schema_version",
        "tool_version",
        "generated_at",
        "request_id",
        "command",
        "ok",
        "error",
    }


def test_hash_json_schema(capsys) -> None:
    code = main(["hash", "GetProcAddress", "--json"])
    assert code == 0
    payload = _load_json_from_stdout(capsys)
    _assert_success_envelope_shape(payload)
    assert payload["command"] == "hash.compute"
    assert "error" not in payload
    assert payload["result"]["algorithm"] == "ror13"
    assert payload["result"]["hash"]["hex"] == "0x7c0dfcaa"


def test_check_json_schema(tmp_path, capsys) -> None:
    sample = tmp_path / "payload.bin"
    sample.write_bytes(b"\x90\x00\x90")
    code = main(["check", str(sample), "--badchars", "00", "--json"])
    assert code == 2
    payload = _load_json_from_stdout(capsys)
    _assert_success_envelope_shape(payload)
    assert payload["command"] == "check.badchars"
    assert payload["result"]["offsets"] == [1]
    assert payload["result"]["match_count"] == 1


def test_encode_json_schema(tmp_path, capsys) -> None:
    sample = tmp_path / "payload.bin"
    encoded = tmp_path / "encoded.bin"
    sample.write_bytes(b"SAFE_FIXTURE")
    code = main(["encode", "xor", str(sample), "--badchars", "00,0a", "--output", str(encoded), "--json"])
    assert code == 0
    payload = _load_json_from_stdout(capsys)
    _assert_success_envelope_shape(payload)
    assert payload["command"] == "encode.xor"
    assert payload["result"]["encoder"] == "xor"
    assert payload["result"]["mode"] == "encode"
    assert payload["result"]["output_path"] == str(encoded.resolve())
    assert encoded.exists()


def test_build_json_schema(tmp_path, capsys) -> None:
    output_file = tmp_path / "demo.txt"
    nasm_file = tmp_path / "demo.asm"
    code = main(
        [
            "build",
            "demo",
            "--arch",
            "x86",
            "--format",
            "hex",
            "--output",
            str(output_file),
            "--emit-nasm",
            str(nasm_file),
            "--json",
        ]
    )
    assert code == 0
    payload = _load_json_from_stdout(capsys)
    _assert_success_envelope_shape(payload)
    assert payload["command"] == "build.demo"
    assert payload["result"]["format"] == "hex"
    assert payload["result"]["output_path"] == str(output_file.resolve())
    assert payload["result"]["nasm_path"] == str(nasm_file.resolve())
    assert output_file.exists()
    assert nasm_file.exists()


def test_hashresolve_and_pe_json_schema_pe32(tmp_path, capsys) -> None:
    pe_file = tmp_path / "fixture.dll"
    pe_file.write_bytes(build_minimal_pe32_with_export(export_name="ExportA", export_rva=0x1234))

    code = main(["pe", "list", str(pe_file), "--json"])
    assert code == 0
    listed = _load_json_from_stdout(capsys)
    _assert_success_envelope_shape(listed)
    assert listed["command"] == "pe.list"
    assert listed["result"]["count"] == 1
    assert listed["result"]["format"] == "PE32"
    assert listed["result"]["machine"]["name"] == "I386"
    assert listed["result"]["image_base"] == 0x400000
    assert listed["result"]["entrypoint_rva"] == 0x1000
    assert len(listed["result"]["sections"]) == 1
    assert listed["result"]["exports"][0]["name"] == "ExportA"

    code = main(["pe", "resolve-name", str(pe_file), "ExportA", "--json"])
    assert code == 0
    resolved_by_name = _load_json_from_stdout(capsys)
    _assert_success_envelope_shape(resolved_by_name)
    assert resolved_by_name["command"] == "pe.resolve_name"
    assert resolved_by_name["result"]["result"]["rva_hex"] == "0x00001234"

    hashed = f"0x{ror13_hash('ExportA'):08x}"
    code = main(["hashresolve", str(pe_file), hashed, "--algorithm", "ror13", "--json"])
    assert code == 0
    resolved_by_hash = _load_json_from_stdout(capsys)
    _assert_success_envelope_shape(resolved_by_hash)
    assert resolved_by_hash["command"] == "hash.resolve"
    assert resolved_by_hash["result"]["result"]["name"] == "ExportA"


def test_pe_list_json_schema_pe32_plus_is_compatible(tmp_path, capsys) -> None:
    pe_file = tmp_path / "fixture64.dll"
    pe_file.write_bytes(build_minimal_pe32_plus_with_export(export_name="Export64", export_rva=0x2233))

    code = main(["pe", "list", str(pe_file), "--json"])
    assert code == 0
    listed = _load_json_from_stdout(capsys)
    _assert_success_envelope_shape(listed)
    assert listed["command"] == "pe.list"
    assert listed["result"]["count"] == 1
    assert listed["result"]["format"] == "PE32+"
    assert listed["result"]["machine"]["name"] == "AMD64"
    assert listed["result"]["image_base"] == 0x140000000
    assert listed["result"]["entrypoint_rva"] == 0x1000
    assert isinstance(listed["result"]["sections"], list)
    assert isinstance(listed["result"]["exports"], list)
    assert listed["result"]["exports"][0]["name"] == "Export64"


def test_json_error_envelope_for_missing_file(capsys) -> None:
    code = main(["pe", "list", "/tmp/shellforge_missing_fixture.bin", "--json"])
    assert code == 3
    payload = _load_json_from_stdout(capsys)
    _assert_error_envelope_shape(payload)
    assert payload["command"] == "pe.list"
    assert "result" not in payload
    assert payload["error"]["code"] == "file_not_found"
    assert payload["error"]["details"]["exception_type"] == "FileNotFoundError"


def test_json_error_envelope_for_invalid_pe_signature(tmp_path, capsys) -> None:
    broken = tmp_path / "broken.bin"
    broken.write_bytes(b"NOT_A_PE")
    code = main(["pe", "list", str(broken), "--json"])
    assert code == 4
    payload = _load_json_from_stdout(capsys)
    _assert_error_envelope_shape(payload)
    assert payload["command"] == "pe.list"
    assert payload["error"]["code"] == "invalid_pe_signature"
    assert payload["error"]["details"]["exception_type"] == "ShellforgeError"


def test_json_error_envelope_for_parse_failure(capsys) -> None:
    code = main(["hash", "--json"])
    assert code == 2
    payload = _load_json_from_stdout(capsys)
    _assert_error_envelope_shape(payload)
    assert payload["command"] == "cli.parse"
    assert payload["error"]["code"] == "invalid_argument"


def test_disasm_json_schema(tmp_path, capsys) -> None:
    sample = tmp_path / "code.bin"
    sample.write_bytes(b"\x90\xc3")
    code = main(["disasm", "--arch", "x86", "--base", "0x1000", str(sample), "--json"])
    assert code == 0
    payload = _load_json_from_stdout(capsys)
    _assert_success_envelope_shape(payload)
    assert payload["command"] == "disasm.analyze"
    assert payload["result"]["arch"] == "x86"
    assert payload["result"]["base_hex"] == "0x1000"
    assert payload["result"]["instruction_count"] == 2
    assert payload["result"]["metadata"]["null_byte_count"] == 0
    assert payload["result"]["instructions"][0]["address_hex"] == "0x1000"
    assert payload["result"]["instructions"][0]["mnemonic"] == "nop"


def test_analyze_json_schema(tmp_path, capsys) -> None:
    sample = tmp_path / "analyze.bin"
    sample.write_bytes(
        b"\x64\xa1\x30\x00\x00\x00" + (b"\x90" * 8) + b"w00tw00t" + b"\xaa\xfc\x0d\x7c" + b"HELLO\x00"
    )
    code = main(
        [
            "analyze",
            "--arch",
            "auto",
            "--window",
            "64",
            "--step",
            "16",
            "--strings-min-len",
            "4",
            "--max-strings",
            "50",
            "--max-hits",
            "25",
            str(sample),
            "--json",
        ]
    )
    assert code == 0
    payload = _load_json_from_stdout(capsys)
    _assert_success_envelope_shape(payload)
    assert payload["command"] == "analyze.static"
    assert payload["result"]["detected_arch"] == "x86"
    assert payload["result"]["detection_confidence"] >= 0.5
    assert payload["result"]["size"] == len(sample.read_bytes())
    assert payload["result"]["heuristics"]
    assert payload["result"]["metadata"]["null_byte_count"] >= 1
    assert len(payload["result"]["peb_walk_signatures"]) >= 1
    assert len(payload["result"]["segment_access_signatures"]) >= 1
    assert len(payload["result"]["nop_regions"]) >= 1
    assert len(payload["result"]["egg_markers"]) >= 1
    assert len(payload["result"]["hash_candidates"]) >= 1
    assert payload["result"]["strings_truncated"] is False
    assert payload["result"]["max_hits"] == 25
    assert any("HELLO" in value for value in payload["result"]["strings"])


def test_analyze_summary_only_json_schema(tmp_path, capsys) -> None:
    sample = tmp_path / "analyze_summary.bin"
    sample.write_bytes(b"\x90" * 32 + b"\x00")
    code = main(["analyze", "--summary-only", str(sample), "--json"])
    assert code == 0
    payload = _load_json_from_stdout(capsys)
    _assert_success_envelope_shape(payload)
    assert payload["command"] == "analyze.static"
    assert "heuristic_hits" in payload["result"]
    assert "likely_decoder" in payload["result"]
    assert "top_heuristics" in payload["result"]
    assert len(payload["result"]["top_heuristics"]) <= 5
    if payload["result"]["top_heuristics"]:
        first = payload["result"]["top_heuristics"][0]
        assert set(first.keys()) == {"name", "confidence"}
    assert "strings" not in payload["result"]


def test_analyze_hash_cross_reference_json_schema(tmp_path, capsys) -> None:
    pe_file = tmp_path / "kernel32_fixture.dll"
    pe_file.write_bytes(build_minimal_pe32_with_export(export_name="GetProcAddress"))
    sample = tmp_path / "analyze_hashxref.bin"
    sample.write_bytes(b"\xaa\xfc\x0d\x7c")

    code = main(["analyze", str(sample), "--hash-db", str(pe_file), "--hash-algorithm", "ror13", "--json"])
    assert code == 0
    payload = _load_json_from_stdout(capsys)
    _assert_success_envelope_shape(payload)
    refs = payload["result"]["hash_cross_references"]
    assert payload["result"]["hash_algorithm"] == "ror13"
    assert str(pe_file.resolve()) in payload["result"]["hash_db_files"]
    assert len(refs) >= 1
    assert refs[0]["hash_hex"] == "0x7c0dfcaa"
    assert any("kernel32_fixture.dll!GetProcAddress" in item for item in refs[0]["matches"])


def test_pe_imports_json_schema(tmp_path, capsys) -> None:
    pe_file = tmp_path / "imports.dll"
    pe_file.write_bytes(build_minimal_pe32_with_imports())

    code = main(["pe", "imports", str(pe_file), "--json"])
    assert code == 0
    payload = _load_json_from_stdout(capsys)
    _assert_success_envelope_shape(payload)
    assert payload["command"] == "pe.imports"
    assert payload["result"]["count"] == 2
    first = payload["result"]["imports"][0]
    assert first["dll"] == "KERNEL32.dll"
    assert first["name"] == "VirtualAlloc"
    assert first["hint"] == 7
    assert first["thunk_rva_hex"] == "0x00001130"
    assert first["iat_rva_hex"] == "0x00001140"


def test_pe_rva_va_file_json_schema(tmp_path, capsys) -> None:
    pe_file = tmp_path / "imports.dll"
    pe_file.write_bytes(build_minimal_pe32_with_imports())

    code = main(["pe", "rva-to-file", str(pe_file), "0x1170", "--json"])
    assert code == 0
    payload = _load_json_from_stdout(capsys)
    _assert_success_envelope_shape(payload)
    assert payload["command"] == "pe.rva_to_file"
    assert payload["result"]["file_offset_hex"] == "0x00000370"
    assert payload["result"]["section"] == ".text"

    code = main(["pe", "file-to-rva", str(pe_file), "0x370", "--json"])
    assert code == 0
    payload = _load_json_from_stdout(capsys)
    _assert_success_envelope_shape(payload)
    assert payload["command"] == "pe.file_to_rva"
    assert payload["result"]["rva_hex"] == "0x00001170"

    code = main(["pe", "rva-to-va", str(pe_file), "0x1170", "--json"])
    assert code == 0
    payload = _load_json_from_stdout(capsys)
    _assert_success_envelope_shape(payload)
    assert payload["command"] == "pe.rva_to_va"
    assert payload["result"]["va_hex"] == "0x401170"

    code = main(["pe", "va-to-rva", str(pe_file), "0x401170", "--json"])
    assert code == 0
    payload = _load_json_from_stdout(capsys)
    _assert_success_envelope_shape(payload)
    assert payload["command"] == "pe.va_to_rva"
    assert payload["result"]["rva_hex"] == "0x00001170"
