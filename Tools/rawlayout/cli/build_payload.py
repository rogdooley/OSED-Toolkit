from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import asdict
from pathlib import Path

from Tools.rawlayout.payload_builder import (
    build_payload,
    format_layout_report_table,
    load_layout_spec,
)


def _parse_key_value(items: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in items:
        if "=" not in raw:
            raise ValueError(f"expected key=value, got {raw!r}")
        key, value = raw.split("=", 1)
        key = key.strip()
        if not key:
            raise ValueError(f"invalid empty key in {raw!r}")
        out[key] = value
    return out


def _parse_params(items: list[str]) -> dict[str, object]:
    base = _parse_key_value(items)
    out: dict[str, object] = {}
    for k, v in base.items():
        try:
            out[k] = int(v, 0)
        except ValueError:
            out[k] = v
    return out


def _parse_external_command_overrides(items: list[str]) -> dict[str, list[str]]:
    pairs = _parse_key_value(items)
    out: dict[str, list[str]] = {}
    for name, raw_json in pairs.items():
        parsed = json.loads(raw_json)
        if not isinstance(parsed, list) or any(not isinstance(x, str) for x in parsed):
            raise ValueError(
                f"external command override for {name!r} must be JSON list[str]"
            )
        out[name] = parsed
    return out


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Build bytes from a declarative JSON/YAML layout spec."
    )
    p.add_argument("--spec", required=True, help="Path to layout spec JSON/YAML file")
    p.add_argument(
        "--param",
        action="append",
        default=[],
        help="Parameter override key=value (repeatable)",
    )
    p.add_argument(
        "--external-command",
        action="append",
        default=[],
        help='External command override name=\'["argv0","arg1"]\' (repeatable)',
    )
    p.add_argument(
        "--external-cmd-json",
        default="",
        help='JSON object mapping command refs to argv arrays, e.g. {"gen":["tool","arg"]}',
    )
    p.add_argument(
        "--external-timeout-s",
        type=float,
        default=10.0,
        help="Default timeout for external command segments",
    )
    p.add_argument(
        "--external-max-output-bytes",
        type=int,
        default=1_000_000,
        help="Default max bytes allowed from external command segments",
    )
    p.add_argument(
        "--fill-byte",
        type=lambda x: int(x, 0),
        default=None,
        help="Override fill byte for unwritten gaps (e.g. 0x41)",
    )
    p.add_argument(
        "--dump-bytes",
        default="",
        help="Write final bytes to this file path",
    )
    p.add_argument(
        "--print-layout-report",
        action="store_true",
        help="Print layout report",
    )
    p.add_argument(
        "--layout-report-format",
        choices=["table", "json"],
        default="table",
        help="Layout report format when --print-layout-report is set",
    )
    p.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose output (includes SHA-256 of payload)",
    )
    return p.parse_args()


def main() -> int:
    args = parse_args()
    spec_path = Path(args.spec)

    try:
        spec = load_layout_spec(spec_path)
        params = _parse_params(args.param)
        cmd_overrides = _parse_external_command_overrides(args.external_command)
        if args.external_cmd_json:
            extra = json.loads(args.external_cmd_json)
            if not isinstance(extra, dict):
                raise ValueError("--external-cmd-json must be a JSON object")
            for name, command in extra.items():
                if (
                    not isinstance(name, str)
                    or not isinstance(command, list)
                    or any(not isinstance(x, str) for x in command)
                ):
                    raise ValueError("--external-cmd-json values must be list[str]")
                cmd_overrides[name] = command

        result = build_payload(
            spec,
            spec_dir=spec_path.parent,
            param_overrides=params,
            external_commands_override=cmd_overrides,
            fill_byte_override=args.fill_byte,
            external_timeout_s=args.external_timeout_s,
            external_max_output_bytes=args.external_max_output_bytes,
        )
    except Exception as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 1

    if args.dump_bytes:
        out_path = Path(args.dump_bytes)
        out_path.write_bytes(result.payload)
        print(f"[*] wrote {len(result.payload)} bytes to {out_path}")
    else:
        print(f"[*] built {len(result.payload)} bytes")

    if args.verbose:
        digest = hashlib.sha256(result.payload).hexdigest()
        print(f"[*] sha256: {digest}")

    if args.print_layout_report:
        if args.layout_report_format == "json":
            printable = {
                "final_length": result.report.final_length,
                "labels": result.report.labels,
                "segments": [asdict(s) for s in result.report.segments],
                "overlaps": [asdict(o) for o in result.report.overlaps],
            }
            print(json.dumps(printable, indent=2, sort_keys=True))
        else:
            print(format_layout_report_table(result.report))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
