"""Tests for the recon Go-binary bridge.

The pure binary-resolution logic is always tested. The end-to-end calls run
only when a built recon binary is available (dist output or RECON_BIN), so the
suite stays green on machines without the Go toolchain.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from Tools.recon_bridge import cli

REPO = Path(__file__).resolve().parents[1]
DIST = REPO / "Tools" / "recon" / "dist"


def _built_binary() -> str | None:
    for name in ("recon", "recon.exe"):
        p = DIST / name
        if p.exists():
            return str(p)
    return None


def test_find_binary_prefers_recon_bin_env(tmp_path, monkeypatch):
    fake = tmp_path / "recon"
    fake.write_text("#!/bin/sh\ntrue\n")
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("RECON_BIN", str(fake))
    assert cli.find_binary() == str(fake)


def test_find_binary_missing_returns_none(tmp_path, monkeypatch):
    monkeypatch.setenv("RECON_BIN", str(tmp_path / "does-not-exist"))
    monkeypatch.setattr(cli.shutil, "which", lambda _name: None)
    # Point the dist search at an empty dir so nothing is found.
    monkeypatch.setattr(cli, "__file__", str(tmp_path / "recon_bridge" / "cli.py"))
    (tmp_path / "recon_bridge").mkdir()
    assert cli.find_binary() is None


def test_main_reports_build_hint_when_missing(capsys, monkeypatch):
    monkeypatch.setattr(cli, "find_binary", lambda: None)
    rc = cli.main(["pe", "whatever.exe"])
    assert rc == 1
    assert "Build it" in capsys.readouterr().err


@pytest.mark.skipif(_built_binary() is None, reason="recon binary not built")
def test_version_passthrough(monkeypatch):
    monkeypatch.setenv("RECON_BIN", _built_binary())
    assert cli.main(["version"]) == 0
