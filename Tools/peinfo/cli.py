"""
CLI entry point for peinfo.

Usage:
    peinfo <pe_file> [--plain] [--json]
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from pathlib import Path

from .analyzer import PEAnalyzer


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="peinfo",
        description="Static PE analysis for exploit development",
    )
    parser.add_argument(
        "pe_file",
        help="Path to PE file (.exe / .dll)",
    )
    parser.add_argument(
        "--plain",
        action="store_true",
        help="Plain-text output (no colors)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="JSON output",
    )

    args = parser.parse_args(argv)
    pe_path = Path(args.pe_file)

    if not pe_path.exists():
        print(f"Error: file not found: {pe_path}", file=sys.stderr)
        sys.exit(1)

    with PEAnalyzer(pe_path) as analyzer:
        report = analyzer.analyze()

    if args.json_output:
        print(json.dumps(dataclasses.asdict(report), indent=2, default=str))
    elif args.plain:
        from .reporter import format_plain
        print(format_plain(report))
    else:
        from .reporter import format_report
        from rich.console import Console
        console = Console()
        format_report(report, console)


if __name__ == "__main__":
    main()
