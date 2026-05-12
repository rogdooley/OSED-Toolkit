from __future__ import annotations

import json
import importlib.util
from pathlib import Path

from shellforge.cli import main
from tests.shellforge.pe_fixture import build_minimal_pe32_with_export, build_minimal_pe32_with_imports

FIXTURES = Path(__file__).parent / "fixtures"


def _read_json_fixture(name: str) -> dict[str, object]:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _load_stdout_json(capsys) -> dict[str, object]:
    return json.loads(capsys.readouterr().out.strip())


def _normalize(value: object, key: str | None = None) -> object:
    if isinstance(value, dict):
        normalized = {k: _normalize(v, k) for k, v in value.items()}
        if "generated_at" in normalized:
            normalized["generated_at"] = "<timestamp>"
        if "request_id" in normalized:
            normalized["request_id"] = "<request_id>"
        if "tool_version" in normalized:
            normalized["tool_version"] = "<version>"
        if normalized.get("error", {}).get("code") == "file_not_found":
            normalized["error"]["message"] = "<file not found>"
        return normalized

    if isinstance(value, list):
        return [_normalize(item) for item in value]

    if key in {"file", "output_path", "nasm_path"} and isinstance(value, str) and value.startswith("/"):
        return "<path>"

    return value


def test_hash_compute_success_snapshot(capsys) -> None:
    code = main(["hash", "GetProcAddress", "--json"])
    assert code == 0
    body = _normalize(_load_stdout_json(capsys))
    assert body == _read_json_fixture("hash/compute/success.json")


def test_check_badchars_success_snapshot(tmp_path, capsys) -> None:
    payload = tmp_path / "payload.bin"
    payload.write_bytes(b"\x90\x00\x90")
    code = main(["check", str(payload), "--badchars", "00", "--json"])
    assert code == 2
    body = _normalize(_load_stdout_json(capsys))
    assert body == _read_json_fixture("check/badchars/success.json")


def test_pe_list_success_snapshot(tmp_path, capsys) -> None:
    pe_file = tmp_path / "fixture.dll"
    pe_file.write_bytes(build_minimal_pe32_with_export(export_name="ExportA", export_rva=0x1234))
    code = main(["pe", "list", str(pe_file), "--json"])
    assert code == 0
    body = _normalize(_load_stdout_json(capsys))
    assert body == _read_json_fixture("pe/list/success.json")


def test_pe_resolve_name_success_snapshot(tmp_path, capsys) -> None:
    pe_file = tmp_path / "fixture.dll"
    pe_file.write_bytes(build_minimal_pe32_with_export(export_name="ExportA", export_rva=0x1234))
    code = main(["pe", "resolve-name", str(pe_file), "ExportA", "--json"])
    assert code == 0
    body = _normalize(_load_stdout_json(capsys))
    assert body == _read_json_fixture("pe/resolve_name/success.json")


def test_pe_list_error_snapshot(capsys) -> None:
    code = main(["pe", "list", "/tmp/shellforge_missing_fixture.bin", "--json"])
    assert code == 3
    body = _normalize(_load_stdout_json(capsys))
    assert body == _read_json_fixture("pe/list/error.json")


def test_pe_imports_success_snapshot(tmp_path, capsys) -> None:
    pe_file = tmp_path / "imports.dll"
    pe_file.write_bytes(build_minimal_pe32_with_imports())
    code = main(["pe", "imports", str(pe_file), "--json"])
    assert code == 0
    body = _normalize(_load_stdout_json(capsys))
    assert body == _read_json_fixture("pe/imports/success.json")


def test_pe_rva_to_file_success_snapshot(tmp_path, capsys) -> None:
    pe_file = tmp_path / "imports.dll"
    pe_file.write_bytes(build_minimal_pe32_with_imports())
    code = main(["pe", "rva-to-file", str(pe_file), "0x1170", "--json"])
    assert code == 0
    body = _normalize(_load_stdout_json(capsys))
    assert body == _read_json_fixture("pe/rva_to_file/success.json")


def test_disasm_success_snapshot(tmp_path, capsys) -> None:
    sample = tmp_path / "code.bin"
    sample.write_bytes(b"\x90\xc3")
    code = main(["disasm", "--arch", "x86", "--base", "0x1000", str(sample), "--json"])
    assert code == 0
    body = _normalize(_load_stdout_json(capsys))
    assert body == _read_json_fixture("disasm/analyze/success.json")


def test_trace_success_snapshot(tmp_path, capsys) -> None:
    if importlib.util.find_spec("unicorn") is None:
        return
    sample = tmp_path / "trace.bin"
    sample.write_bytes(b"\x90\xc3")
    code = main(["trace", "--arch", "x86", "--base", "0x1000", "--steps", "10", str(sample), "--json"])
    assert code == 0
    body = _normalize(_load_stdout_json(capsys))
    assert body == _read_json_fixture("trace/analyze/success.json")
