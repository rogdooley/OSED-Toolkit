"""
Build a portable peinfo bundle for air-gapped Windows machines.

Run on a Linux/macOS machine with internet access:

    python -m Tools.peinfo.bundle [--output peinfo_portable.zip]

Produces a zip containing:
    peinfo_portable/
        peinfo.py          -- single-file entry point
        peinfo_lib/        -- analyzer + reporter modules
        pefile.py           -- vendored pefile (pure Python)
        README.txt

On the target Windows machine:
    python peinfo.py target.exe
"""

from __future__ import annotations

import argparse
import importlib
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path


STANDALONE_ENTRY = '''\
#!/usr/bin/env python3
"""
peinfo -- portable single-file entry point.

Usage:
    python peinfo.py <target.exe> [--plain] [--json]

Drop this alongside the peinfo_lib/ folder and pefile.py.
"""
import sys
import os

script_dir = os.path.dirname(os.path.abspath(__file__))
if script_dir not in sys.path:
    sys.path.insert(0, script_dir)

import argparse
import dataclasses
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(
        prog="peinfo",
        description="Static PE analysis for exploit development",
    )
    parser.add_argument("pe_file", help="Path to PE file (.exe / .dll)")
    parser.add_argument("--plain", action="store_true",
                        help="Plain-text output (no colors)")
    parser.add_argument("--json", action="store_true", dest="json_output",
                        help="JSON output")
    args = parser.parse_args()

    pe_path = Path(args.pe_file)
    if not pe_path.exists():
        print(f"Error: file not found: {pe_path}", file=sys.stderr)
        sys.exit(1)

    from peinfo_lib.analyzer import PEAnalyzer
    with PEAnalyzer(pe_path) as analyzer:
        report = analyzer.analyze()

    if args.json_output:
        print(json.dumps(dataclasses.asdict(report), indent=2, default=str))
    elif args.plain:
        from peinfo_lib.reporter import format_plain
        print(format_plain(report))
    else:
        from peinfo_lib.reporter import format_report
        format_report(report)


if __name__ == "__main__":
    main()
'''

README_TEXT = """\
peinfo -- Portable PE Analysis for Exploit Development
=======================================================

Requirements:
  Python 3.10+ (tested with 3.12)
  No internet connection needed.
  No pip install needed -- pefile is vendored.

Usage:
  python peinfo.py <target.exe>
  python peinfo.py <target.exe> --plain
  python peinfo.py <target.exe> --json

If 'rich' is installed (pip install rich), the default output uses
colored formatting.  Otherwise it falls back to plain text automatically.

Files:
  peinfo.py        -- run this
  peinfo_lib/      -- analysis engine and reporter
  pefile.py        -- vendored PE parser (pure Python, no dependencies)
  ordlookup/       -- vendored ordinal lookup tables (used by pefile)
"""


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Bundle peinfo for portable deployment",
    )
    parser.add_argument(
        "--output", "-o",
        default="peinfo_portable.zip",
        help="Output zip path (default: peinfo_portable.zip)",
    )
    args = parser.parse_args()

    this_dir = Path(__file__).resolve().parent

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "peinfo_portable"
        root.mkdir()

        (root / "peinfo.py").write_text(STANDALONE_ENTRY)
        (root / "README.txt").write_text(README_TEXT)

        lib_dir = root / "peinfo_lib"
        lib_dir.mkdir()
        (lib_dir / "__init__.py").write_text("")
        shutil.copy2(this_dir / "analyzer.py", lib_dir / "analyzer.py")
        shutil.copy2(this_dir / "reporter.py", lib_dir / "reporter.py")

        pefile_path = _find_pefile()
        if pefile_path is None:
            print("Error: pefile not found. Install it: pip install pefile",
                  file=sys.stderr)
            sys.exit(1)

        if pefile_path.is_file():
            shutil.copy2(pefile_path, root / "pefile.py")
        elif pefile_path.is_dir():
            shutil.copytree(pefile_path, root / "pefile")

        ordlookup_path = _find_ordlookup()
        if ordlookup_path and ordlookup_path.is_dir():
            shutil.copytree(ordlookup_path, root / "ordlookup")

        out_path = Path(args.output)
        with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for fpath in sorted(root.rglob("*")):
                if fpath.is_file() and "__pycache__" not in str(fpath):
                    arcname = fpath.relative_to(root.parent)
                    zf.write(fpath, arcname)

        size_kb = out_path.stat().st_size / 1024
        print(f"[+] Bundle created: {out_path} ({size_kb:.0f} KB)")
        print(f"[+] Extract and run: python peinfo_portable/peinfo.py target.exe")


def _find_pefile() -> Path | None:
    try:
        mod = importlib.import_module("pefile")
        p = Path(mod.__file__).resolve()
        if p.name == "__init__.py":
            return p.parent
        return p
    except ImportError:
        return None


def _find_ordlookup() -> Path | None:
    try:
        mod = importlib.import_module("ordlookup")
        p = Path(mod.__file__).resolve()
        if p.name == "__init__.py":
            return p.parent
        return p.parent if p.is_file() else None
    except ImportError:
        return None


if __name__ == "__main__":
    main()
