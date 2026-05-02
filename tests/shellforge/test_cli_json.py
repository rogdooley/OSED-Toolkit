from __future__ import annotations

import json
from datetime import datetime
import re

from shellforge.cli import main
from shellforge.hashes.ror13 import ror13_hash
from tests.shellforge.pe_fixture import build_minimal_pe32_plus_with_export, build_minimal_pe32_with_export


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
