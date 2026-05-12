from __future__ import annotations

import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SKELETON = REPO_ROOT / "Exploits" / "windows_x86" / "skeleton.py"


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SKELETON), *args],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def test_hash_only_mode_runs() -> None:
    result = _run("--hash-only", "LoadLibraryA")
    assert result.returncode == 0
    assert "LoadLibraryA" in result.stdout
    assert "ROR-13" in result.stdout


def test_list_snippets_mode_runs() -> None:
    result = _run("--list-snippets")
    assert result.returncode == 0
    assert "Snippet descriptions:" in result.stdout
    assert "startupinfoa_socket" in result.stdout


def test_show_asm_bindshell_mode_runs_without_execution() -> None:
    result = _run("--show-asm", "--mode", "bindshell", "--port", "4444")
    assert result.returncode == 0
    assert "Mode     : bindshell port 4444" in result.stdout
    assert "Algorithm: ROR-13" in result.stdout


def test_show_asm_revshell_mode_runs_without_execution() -> None:
    result = _run(
        "--show-asm",
        "--mode",
        "revshell",
        "--lhost",
        "192.168.45.174",
        "--lport",
        "443",
    )
    assert result.returncode == 0
    assert "Mode     : revshell -> 192.168.45.174:443" in result.stdout
    assert "Algorithm: ROR-13" in result.stdout


def test_show_asm_custom_multifunction_mode_runs() -> None:
    result = _run(
        "--show-asm",
        "--functions",
        "LoadLibraryA,CreateProcessA,TerminateProcess",
    )
    assert result.returncode == 0
    assert "Mode     : custom: LoadLibraryA, CreateProcessA, TerminateProcess" in result.stdout
    assert "Algorithm: ROR-13" in result.stdout
