#!/usr/bin/env python3

import argparse
import json
import sys

from Tools.crashtriage.formatter import format_human, format_json
from Tools.crashtriage.models import TriageResult
from Tools.crashtriage.parser import parse_dump
from Tools.crashtriage.ranker import infer_arch, rank_candidates
from Tools.crashtriage.recommend import build_recommendations


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Parse debugger crash output and recommend pattern offset triage commands"
    )
    parser.add_argument(
        "--input",
        help="Path to crash dump text file. If omitted, reads from stdin.",
    )
    parser.add_argument(
        "-l",
        "--length",
        required=True,
        type=int,
        help="Original cyclic pattern length used for the crash run.",
    )
    parser.add_argument(
        "--arch",
        choices=["x86", "x64", "auto"],
        default="auto",
        help="Target architecture. Defaults to auto-detect.",
    )
    parser.add_argument(
        "--endianness",
        choices=["little", "big"],
        default="little",
        help="Target endianness for recommended pattern offset commands.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON output instead of human-readable text.",
    )
    parser.add_argument(
        "--all-candidates",
        action="store_true",
        help="Emit recommendations for all candidates instead of top 3.",
    )
    return parser.parse_args()


def _read_input(path: str | None) -> str:
    if path:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read()
    return sys.stdin.read()


def main() -> int:
    try:
        args = parse_args()
        if args.length <= 0:
            print("[-] Error: --length must be a positive integer", file=sys.stderr)
            return 1

        text = _read_input(args.input)
        if not text.strip():
            print("[-] Error: no crash text provided", file=sys.stderr)
            return 2

        parsed = parse_dump(text)
        arch = infer_arch(parsed, args.arch)
        candidates = rank_candidates(parsed, arch)
        recommendations, notes = build_recommendations(
            candidates,
            length=args.length,
            arch=arch,
            endianness=args.endianness,
            all_candidates=args.all_candidates,
        )
        result = TriageResult(
            detected_arch=arch,
            endianness=args.endianness,
            exception=parsed.exception,
            candidates=candidates if args.all_candidates else candidates[:3],
            recommendations=recommendations,
            notes=notes,
        )

    except Exception as exc:
        print(f"[-] Error: {exc}", file=sys.stderr)
        return 1

    if not candidates:
        error_payload = format_json(result) if args.json else format_human(result)
        if args.json:
            print(json.dumps(error_payload, indent=2))
        else:
            print(error_payload)
        return 2

    if args.json:
        print(json.dumps(format_json(result), indent=2))
    else:
        print(format_human(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
