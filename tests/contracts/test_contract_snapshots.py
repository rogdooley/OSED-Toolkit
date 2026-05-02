from __future__ import annotations

import json
from pathlib import Path

from shellforge.cli import main
from tests.shellforge.pe_fixture import build_minimal_pe32_with_export

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
