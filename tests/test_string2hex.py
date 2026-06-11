from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "Tools" / "Value_Conversion_Scripts" / "string2hex.py"


def load_module():
    spec = importlib.util.spec_from_file_location("string2hex", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_chunking_and_little_endian_format():
    module = load_module()

    chunks = module.format_chunks("ABCD123", chunk_size=4)

    assert [chunk.little_endian_hex for chunk in chunks] == ["0x44434241", "0x00333231"]
    assert chunks[0].contains_null is False
    assert chunks[1].contains_null is True


def test_output_mentions_null_byte_mitigation():
    module = load_module()

    output = module.build_output("A\x00B", chunk_size=4)

    assert "Null bytes detected" in output
    assert "runtime reconstruction strategy" in output


def test_wide_string_output_mentions_utf16le():
    module = load_module()

    output = module.build_output("AB", chunk_size=4, string_format="wide")

    assert "String format: wide" in output
    assert "utf-16le" in output
    assert "UTF-16LE" in output


def test_render_multiple_inputs():
    module = load_module()

    output = module.render_inputs(
        ["ABCD", "EF"],
        encoding="utf-8",
        chunk_size=4,
        architecture="x86",
        output_mode="push",
    )

    assert "Item 1/2" in output
    assert "Item 2/2" in output
    assert "push 0x44434241" in output
    assert "push 0x00004645" in output


def test_file_input(tmp_path: Path):
    module = load_module()

    source = tmp_path / "strings.txt"
    source.write_text("ABCD\n\nEFGH\n", encoding="utf-8")

    args = module.parse_args(["--file", str(source), "--format", "hex"])
    texts = module.load_inputs(args)

    assert texts == ["ABCD", "EFGH"]


def test_ip_subcommand_renders_hex_and_push():
    module = load_module()

    args = module.parse_args(["ip", "192.168.1.2", "--format", "both"])
    ips = module.load_ip_inputs(args)

    assert ips == ["192.168.1.2"]

    output = module.render_ip_inputs(ips, output_mode="both")

    assert "0x0201a8c0" in output
    assert "push 0x0201a8c0" in output


def test_x64_push_sequence_for_eight_byte_chunk():
    module = load_module()

    output = module.build_output("ABCDEFGH", chunk_size=8, architecture="x64", output_mode="push")

    assert "mov rax, 0x4847464544434241" in output
    assert "push rax" in output


def test_cli_executes_successfully():
    completed = subprocess.run(
        [sys.executable, str(SCRIPT_PATH), "ABCD"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0
    assert "0x44434241" in completed.stdout


def test_installed_entry_point_smoke(tmp_path: Path):
    completed = subprocess.run(
        ["uv", "run", "value-convert", "ip", "192.168.1.2"],
        check=False,
        capture_output=True,
        text=True,
        env={**os.environ, "UV_CACHE_DIR": str(tmp_path / "uv-cache")},
    )

    assert completed.returncode == 0
    assert "0x0201a8c0" in completed.stdout


def test_deprecated_ip2hex_wrapper_runs():
    wrapper = SCRIPT_PATH.with_name("ip2hex.py")
    completed = subprocess.run(
        [sys.executable, str(wrapper), "192.168.1.2"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0
    assert "deprecated" in completed.stderr.lower()
    assert "0x0201a8c0" in completed.stdout
