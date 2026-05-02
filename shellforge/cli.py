from __future__ import annotations

import argparse
import json
import pathlib
import sys
import traceback

from shellforge.analysis.badchars import find_badchars, parse_badchars
from shellforge.analysis.pe_exports import (
    PEExport,
    PESection,
    PortableExecutable,
    parse_portable_executable_from_path,
    resolve_export_by_hash,
    resolve_export_by_name,
)
from shellforge.builder import ShellcodeBuilder
from shellforge.contracts.commands import CommandId
from shellforge.contracts.envelope import ResponseEnvelope
from shellforge.contracts.errors import ErrorCode, ShellforgeError
from shellforge.contracts.exception_mapper import ExceptionMapper
from shellforge.contracts.exit_codes import ExitCodeMapper
from shellforge.encoders.xor import decode_xor, encode_xor, select_xor_key
from shellforge.hashes import HASHERS
from shellforge.model import Architecture, BuildRequest, OutputFormat
from shellforge.output import FORMATTERS
from shellforge.registry import get_hash_providers


class ShellforgeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # pragma: no cover - exercised via main behavior
        raise ValueError(message)


def _parse_arch(value: str) -> Architecture:
    return Architecture(value)


def _parse_format(value: str) -> OutputFormat:
    return OutputFormat(value)


def _read_bytes(path: str) -> bytes:
    return pathlib.Path(path).read_bytes()


def _write_output(data: bytes | str, out_path: str | None) -> None:
    if out_path:
        target = pathlib.Path(out_path)
        if isinstance(data, bytes):
            target.write_bytes(data)
        else:
            target.write_text(data + "\n", encoding="utf-8")
        return

    if isinstance(data, bytes):
        sys.stdout.buffer.write(data)
    else:
        print(data)


def _emit_json(payload: dict[str, object]) -> None:
    print(json.dumps(payload, sort_keys=True))


def _json_success(command: CommandId | str, result: dict[str, object]) -> None:
    _emit_json(ResponseEnvelope.success(command=str(command), result=result))


def _command_name(args: argparse.Namespace) -> str:
    if args.command == "build":
        if args.payload == "demo":
            return CommandId.BUILD_DEMO.value
        if args.payload == "calc":
            return CommandId.BUILD_CALC.value
        return f"build.{args.payload}"
    if args.command == "hash":
        return CommandId.HASH_COMPUTE.value
    if args.command == "hashresolve":
        return CommandId.HASH_RESOLVE.value
    if args.command == "check":
        return CommandId.CHECK_BADCHARS.value
    if args.command == "encode":
        if getattr(args, "decode", False):
            return CommandId.ENCODE_DECODE.value
        return CommandId.ENCODE_XOR.value
    if args.command == "pe":
        if args.pe_command == "list":
            return CommandId.PE_LIST.value
        if args.pe_command == "resolve-name":
            return CommandId.PE_RESOLVE_NAME.value
        if args.pe_command == "resolve-hash":
            return CommandId.PE_RESOLVE_HASH.value
    return f"cli.{args.command}"


def _export_to_json(export: PEExport) -> dict[str, object]:
    return {
        "ordinal": export.ordinal,
        "name": export.name,
        "rva": export.rva,
        "rva_hex": f"0x{export.rva:08x}",
    }


def _section_to_json(section: PESection) -> dict[str, object]:
    return {
        "name": section.name,
        "virtual_address": section.virtual_address,
        "virtual_address_hex": f"0x{section.virtual_address:08x}",
        "virtual_size": section.virtual_size,
        "pointer_to_raw_data": section.pointer_to_raw_data,
        "pointer_to_raw_data_hex": f"0x{section.pointer_to_raw_data:08x}",
        "size_of_raw_data": section.size_of_raw_data,
    }


def _pe_to_json(pe: PortableExecutable) -> dict[str, object]:
    return {
        "machine": {
            "value": pe.machine,
            "hex": f"0x{pe.machine:04x}",
            "name": pe.machine_name,
        },
        "format": pe.format,
        "image_base": pe.image_base,
        "image_base_hex": f"0x{pe.image_base:x}",
        "entrypoint_rva": pe.entrypoint_rva,
        "entrypoint_rva_hex": f"0x{pe.entrypoint_rva:08x}",
        "sections": [_section_to_json(section) for section in pe.sections],
        "exports": [_export_to_json(item) for item in pe.exports],
    }


def _format_human_error(command: str, code: ErrorCode, message: str, details: dict[str, object], verbose: bool) -> str:
    exception_type = details.get("exception_type")
    if verbose and exception_type:
        header = f"ERROR [{command}][{code.value}][{exception_type}]"
    else:
        header = f"ERROR [{command}][{code.value}]"
    lines = [header, message]
    if verbose:
        extra = {k: v for k, v in details.items() if k != "exception_type"}
        for key in sorted(extra):
            lines.append(f"{key}={extra[key]}")
    return "\n".join(lines)


def _cmd_build(args: argparse.Namespace) -> int:
    builder = ShellcodeBuilder()
    request = BuildRequest(
        payload=args.payload,
        architecture=_parse_arch(args.arch),
        badchars=parse_badchars(args.badchars),
        egg_marker=args.egg_marker,
    )
    artifact = builder.build(request)

    if args.emit_nasm:
        if artifact.nasm_source is None:
            raise ValueError("selected payload did not emit a NASM reference")
        pathlib.Path(args.emit_nasm).write_text(artifact.nasm_source + "\n", encoding="utf-8")

    formatter = FORMATTERS[_parse_format(args.format).value]
    rendered = formatter(artifact.payload_bytes)
    if args.output:
        _write_output(rendered, args.output)
    elif not args.json:
        _write_output(rendered, None)

    if args.json:
        _json_success(
            _command_name(args),
            {
                "payload": args.payload,
                "arch": args.arch,
                "format": args.format,
                "payload_size": len(artifact.payload_bytes),
                "output_path": str(pathlib.Path(args.output).resolve()) if args.output else None,
                "nasm_path": str(pathlib.Path(args.emit_nasm).resolve()) if args.emit_nasm else None,
                "metadata": artifact.metadata,
            },
        )
    return ExitCodeMapper.SUCCESS


def _cmd_hash(args: argparse.Namespace) -> int:
    provider = get_hash_providers()[args.algorithm]
    value = provider.compute(args.symbol)
    if args.json:
        _json_success(
            CommandId.HASH_COMPUTE,
            {
                "algorithm": args.algorithm,
                "symbol": args.symbol,
                "hash": {"value": value, "hex": f"0x{value:08x}"},
            },
        )
    else:
        print(f"0x{value:08x}")
    return ExitCodeMapper.SUCCESS


def _cmd_hashresolve(args: argparse.Namespace) -> int:
    hash_provider = get_hash_providers()[args.algorithm]
    target_hash = int(args.hash_value, 16)
    parsed = parse_portable_executable_from_path(args.file)
    result = resolve_export_by_hash(parsed.exports, target_hash, hash_provider)
    if result is None:
        raise ShellforgeError(
            ErrorCode.INVALID_ARGUMENT,
            "export hash not found",
            details={
                "algorithm": args.algorithm,
                "file": str(pathlib.Path(args.file).resolve()),
                "hash": f"0x{target_hash:08x}",
                "format": parsed.format,
            },
        )

    if args.json:
        _json_success(
            CommandId.HASH_RESOLVE,
            {
                "algorithm": args.algorithm,
                "file": str(pathlib.Path(args.file).resolve()),
                "hash": {"value": target_hash, "hex": f"0x{target_hash:08x}"},
                "format": parsed.format,
                "result": _export_to_json(result),
            },
        )
    else:
        print(f"{result.name} ordinal={result.ordinal} rva=0x{result.rva:08x}")
    return ExitCodeMapper.SUCCESS


def _cmd_check(args: argparse.Namespace) -> int:
    payload = _read_bytes(args.file)
    badchars = parse_badchars(args.badchars)
    offsets = find_badchars(payload, badchars)
    if args.json:
        _json_success(
            CommandId.CHECK_BADCHARS,
            {
                "file": str(pathlib.Path(args.file).resolve()),
                "badchars": [f"0x{byte:02x}" for byte in badchars],
                "offsets": offsets,
                "match_count": len(offsets),
                "size": len(payload),
            },
        )
    else:
        if offsets:
            print("badchars found at offsets:", ",".join(str(idx) for idx in offsets))
        else:
            print("no badchars found")
    return ExitCodeMapper.SUCCESS if not offsets else ExitCodeMapper.INVALID_ARGS


def _cmd_encode(args: argparse.Namespace) -> int:
    payload = _read_bytes(args.file)
    badchars = parse_badchars(args.badchars)
    mode = "decode" if args.decode else "encode"

    if args.decode:
        if not args.key:
            raise ValueError("--key is required for decode")
        key = int(args.key, 16)
        decoded = decode_xor(payload, key)
        if not args.json:
            _write_output(decoded, args.output)
        if args.json:
            _json_success(
                CommandId.ENCODE_DECODE,
                {
                    "encoder": "xor",
                    "mode": mode,
                    "file": str(pathlib.Path(args.file).resolve()),
                    "input_size": len(payload),
                    "output_size": len(decoded),
                    "key": {"value": key, "hex": f"0x{key:02x}"},
                    "output_path": str(pathlib.Path(args.output).resolve()) if args.output else None,
                },
            )
        return ExitCodeMapper.SUCCESS

    key = int(args.key, 16) if args.key else select_xor_key(payload, badchars)
    encoded = encode_xor(payload, key)
    if badchars and find_badchars(encoded, badchars):
        raise ValueError("encoded output still contains requested badchars")

    if not args.json:
        if args.output:
            pathlib.Path(args.output).write_bytes(encoded)
        else:
            sys.stdout.buffer.write(encoded)
        print(f"\nkey=0x{key:02x}", file=sys.stderr)

    if args.json:
        if args.output:
            pathlib.Path(args.output).write_bytes(encoded)
        _json_success(
            CommandId.ENCODE_XOR,
            {
                "encoder": "xor",
                "mode": mode,
                "file": str(pathlib.Path(args.file).resolve()),
                "input_size": len(payload),
                "output_size": len(encoded),
                "key": {"value": key, "hex": f"0x{key:02x}"},
                "badchars": [f"0x{byte:02x}" for byte in badchars],
                "output_path": str(pathlib.Path(args.output).resolve()) if args.output else None,
            },
        )
    return ExitCodeMapper.SUCCESS


def _cmd_pe_list(args: argparse.Namespace) -> int:
    parsed = parse_portable_executable_from_path(args.file)
    if args.json:
        payload = _pe_to_json(parsed)
        payload.update(
            {
                "file": str(pathlib.Path(args.file).resolve()),
                "count": len(parsed.exports),
            }
        )
        _json_success(CommandId.PE_LIST, payload)
        return ExitCodeMapper.SUCCESS

    if not parsed.exports:
        print("no exports found")
        return ExitCodeMapper.SUCCESS
    for item in parsed.exports:
        print(f"{item.ordinal:5d}  {item.name:<40} rva=0x{item.rva:08x}")
    return ExitCodeMapper.SUCCESS


def _cmd_pe_resolve_name(args: argparse.Namespace) -> int:
    parsed = parse_portable_executable_from_path(args.file)
    result = resolve_export_by_name(parsed.exports, args.name)
    if result is None:
        raise ShellforgeError(
            ErrorCode.INVALID_ARGUMENT,
            "export name not found",
            details={
                "query": args.name,
                "file": str(pathlib.Path(args.file).resolve()),
                "format": parsed.format,
            },
        )

    if args.json:
        _json_success(
            CommandId.PE_RESOLVE_NAME,
            {
                "file": str(pathlib.Path(args.file).resolve()),
                "query": args.name,
                "format": parsed.format,
                "result": _export_to_json(result),
            },
        )
    else:
        print(f"{result.name} ordinal={result.ordinal} rva=0x{result.rva:08x}")
    return ExitCodeMapper.SUCCESS


def _cmd_pe_resolve_hash(args: argparse.Namespace) -> int:
    parsed = parse_portable_executable_from_path(args.file)
    provider = get_hash_providers()[args.algorithm]
    target_hash = int(args.hash_value, 16)
    result = resolve_export_by_hash(parsed.exports, target_hash, provider)
    if result is None:
        raise ShellforgeError(
            ErrorCode.INVALID_ARGUMENT,
            "export hash not found",
            details={
                "algorithm": args.algorithm,
                "hash": f"0x{target_hash:08x}",
                "file": str(pathlib.Path(args.file).resolve()),
                "format": parsed.format,
            },
        )

    if args.json:
        _json_success(
            CommandId.PE_RESOLVE_HASH,
            {
                "file": str(pathlib.Path(args.file).resolve()),
                "algorithm": args.algorithm,
                "hash": {"value": target_hash, "hex": f"0x{target_hash:08x}"},
                "format": parsed.format,
                "result": _export_to_json(result),
            },
        )
    else:
        print(f"{result.name} ordinal={result.ordinal} rva=0x{result.rva:08x}")
    return ExitCodeMapper.SUCCESS


def build_parser() -> argparse.ArgumentParser:
    parser = ShellforgeArgumentParser(prog="shellforge", description="Shellforge analysis and packaging framework")
    parser.add_argument("--verbose", action="store_true", help="show detailed mapped error details")
    parser.add_argument("--debug", action="store_true", help="show traceback on errors")
    sub = parser.add_subparsers(dest="command", required=True, parser_class=ShellforgeArgumentParser)

    build_cmd = sub.add_parser("build", help="Build a non-operational payload artifact")
    build_cmd.add_argument("payload", help="payload provider name (e.g. demo)")
    build_cmd.add_argument("--arch", default="x86", choices=[arch.value for arch in Architecture])
    build_cmd.add_argument("--format", default="hex", choices=[fmt.value for fmt in OutputFormat])
    build_cmd.add_argument("--output", help="output file")
    build_cmd.add_argument("--emit-nasm", help="emit NASM reference to file")
    build_cmd.add_argument("--badchars", default="", help="comma-separated hex bytes (e.g. 00,0a,0d)")
    build_cmd.add_argument("--egg-marker", default=None, help="4-byte egg marker")
    build_cmd.add_argument("--json", action="store_true", help="emit JSON metadata")
    build_cmd.set_defaults(handler=_cmd_build)

    hash_cmd = sub.add_parser("hash", help="Compute symbol hash")
    hash_cmd.add_argument("symbol")
    hash_cmd.add_argument("--algorithm", default="ror13", choices=sorted(HASHERS.keys()))
    hash_cmd.add_argument("--json", action="store_true", help="emit JSON")
    hash_cmd.set_defaults(handler=_cmd_hash)

    resolve_cmd = sub.add_parser("hashresolve", help="Resolve hash in PE exports")
    resolve_cmd.add_argument("file", help="path to PE file (PE32 or PE32+)")
    resolve_cmd.add_argument("hash_value", help="hash in hex, e.g. 0x1234abcd")
    resolve_cmd.add_argument("--algorithm", default="ror13", choices=sorted(HASHERS.keys()))
    resolve_cmd.add_argument("--json", action="store_true", help="emit JSON")
    resolve_cmd.set_defaults(handler=_cmd_hashresolve)

    check_cmd = sub.add_parser("check", help="Scan payload bytes for badchars")
    check_cmd.add_argument("file")
    check_cmd.add_argument("--badchars", required=True)
    check_cmd.add_argument("--json", action="store_true", help="emit JSON")
    check_cmd.set_defaults(handler=_cmd_check)

    encode_cmd = sub.add_parser("encode", help="Encode/decode payload bytes")
    encode_sub = encode_cmd.add_subparsers(dest="encoder", required=True, parser_class=ShellforgeArgumentParser)
    xor_cmd = encode_sub.add_parser("xor", help="XOR encode/decode")
    xor_cmd.add_argument("file")
    xor_cmd.add_argument("--badchars", default="")
    xor_cmd.add_argument("--key", help="manual key in hex (e.g. aa)")
    xor_cmd.add_argument("--decode", action="store_true")
    xor_cmd.add_argument("--output", help="output file")
    xor_cmd.add_argument("--json", action="store_true", help="emit JSON metadata")
    xor_cmd.set_defaults(handler=_cmd_encode)

    pe_cmd = sub.add_parser("pe", help="PE export analysis (PE32 and PE32+)")
    pe_sub = pe_cmd.add_subparsers(dest="pe_command", required=True, parser_class=ShellforgeArgumentParser)

    pe_list = pe_sub.add_parser("list", help="List exports from a PE file")
    pe_list.add_argument("file")
    pe_list.add_argument("--json", action="store_true", help="emit JSON")
    pe_list.set_defaults(handler=_cmd_pe_list)

    pe_name = pe_sub.add_parser("resolve-name", help="Resolve export by name")
    pe_name.add_argument("file")
    pe_name.add_argument("name")
    pe_name.add_argument("--json", action="store_true", help="emit JSON")
    pe_name.set_defaults(handler=_cmd_pe_resolve_name)

    pe_hash = pe_sub.add_parser("resolve-hash", help="Resolve export by hash")
    pe_hash.add_argument("file")
    pe_hash.add_argument("hash_value")
    pe_hash.add_argument("--algorithm", default="ror13", choices=sorted(HASHERS.keys()))
    pe_hash.add_argument("--json", action="store_true", help="emit JSON")
    pe_hash.set_defaults(handler=_cmd_pe_resolve_hash)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    candidate_argv = argv if argv is not None else sys.argv[1:]
    json_mode = "--json" in candidate_argv
    verbose_mode = "--verbose" in candidate_argv
    debug_mode = "--debug" in candidate_argv

    try:
        args = parser.parse_args(argv)
    except Exception as exc:  # noqa: BLE001
        code, message, details = ExceptionMapper.to_error(exc)
        exit_code = ExitCodeMapper.from_error_code(code)
        if json_mode:
            _emit_json(
                ResponseEnvelope.error(command=CommandId.CLI_PARSE.value, code=code, message=message, details=details)
            )
            return exit_code
        print(_format_human_error(CommandId.CLI_PARSE.value, code, message, details, verbose_mode), file=sys.stderr)
        if debug_mode:
            traceback.print_exc()
        return exit_code

    try:
        return args.handler(args)
    except Exception as exc:  # noqa: BLE001
        code, message, details = ExceptionMapper.to_error(exc)
        exit_code = ExitCodeMapper.from_error_code(code)
        if getattr(args, "json", False):
            _emit_json(ResponseEnvelope.error(command=_command_name(args), code=code, message=message, details=details))
            return exit_code
        print(_format_human_error(_command_name(args), code, message, details, args.verbose), file=sys.stderr)
        if args.debug:
            traceback.print_exc()
        return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
