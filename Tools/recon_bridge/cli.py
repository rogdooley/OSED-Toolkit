"""Locate and drive the recon Go binary from Python."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Optional

BUILD_HINT = "recon binary not found. Build it: cd Tools/recon && ./build.sh"


def find_binary() -> Optional[str]:
    """Return a path to the recon executable, or None if it cannot be found.

    Search order: RECON_BIN env var, the repo's Tools/recon/dist build output,
    then a `recon` on PATH.
    """
    env = os.environ.get("RECON_BIN")
    if env and os.path.exists(env):
        return env

    exe = "recon.exe" if os.name == "nt" else "recon"
    # cli.py -> recon_bridge -> Tools -> repo root
    repo = Path(__file__).resolve().parents[2]
    dist = repo / "Tools" / "recon" / "dist"
    for cand in (dist / exe, dist / "recon", dist / "recon.exe"):
        if cand.exists():
            return str(cand)

    found = shutil.which("recon")
    if found:
        return found
    return None


def _run_json(subcommand: str, args: list[str]) -> Any:
    binary = find_binary()
    if not binary:
        raise FileNotFoundError(BUILD_HINT)
    cmd = [binary, subcommand, "--json", *args]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"recon {subcommand} failed: {proc.stderr.strip()}")
    return json.loads(proc.stdout)


def pe(path: str) -> dict:
    """Static PE analysis as a dict (mitigations, sections, imports, ...)."""
    return _run_json("pe", [path])


def triage(path: str, top: int = 0) -> list[dict]:
    """Ranked functions for a PE file. top=0 returns all scored functions."""
    return _run_json("triage", ["--top", str(top), path])


def cdb(dump_path: str, top: int = 0) -> list[dict]:
    """Ranked functions parsed from a headless-cdb `uf` text dump."""
    return _run_json("cdb", ["--top", str(top), dump_path])


def main(argv: Optional[list[str]] = None) -> int:
    """Pass-through entry point: `recon <subcommand> ...` runs the binary."""
    argv = list(sys.argv[1:] if argv is None else argv)
    binary = find_binary()
    if not binary:
        print(BUILD_HINT, file=sys.stderr)
        return 1
    try:
        return subprocess.run([binary, *argv]).returncode
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
