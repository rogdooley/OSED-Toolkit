from __future__ import annotations

import argparse
import json
import pathlib
import sys
import traceback

from shellforge.analysis.badchars import find_badchars, parse_badchars
from shellforge.analysis.analyze import analyze_bytes, build_hash_cross_reference
from shellforge.analysis.disasm import disassemble_bytes
from shellforge.analysis.pe_exports import (
    PEExport,
    PEImport,
    PESection,
    PortableExecutable,
    file_offset_to_rva,
    find_section_for_rva,
    parse_portable_executable_from_path,
    rva_to_file_offset,
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
        if args.pe_command == "imports":
            return CommandId.PE_IMPORTS.value
        if args.pe_command == "rva-to-file":
            return CommandId.PE_RVA_TO_FILE.value
        if args.pe_command == "file-to-rva":
            return CommandId.PE_FILE_TO_RVA.value
        if args.pe_command == "rva-to-va":
            return CommandId.PE_RVA_TO_VA.value
        if args.pe_command == "va-to-rva":
            return CommandId.PE_VA_TO_RVA.value
    if args.command == "disasm":
        return CommandId.DISASM_ANALYZE.value
    if args.command == "analyze":
        return CommandId.ANALYZE_STATIC.value
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


def _import_to_json(item: PEImport) -> dict[str, object]:
    return {
        "dll": item.dll,
        "name": item.name,
        "ordinal": item.ordinal,
        "hint": item.hint,
        "thunk_rva": item.thunk_rva,
        "thunk_rva_hex": f"0x{item.thunk_rva:08x}",
        "iat_rva": item.iat_rva,
        "iat_rva_hex": f"0x{item.iat_rva:08x}",
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


def _parse_int(value: str) -> int:
    return int(value, 0)


def _cmd_pe_imports(args: argparse.Namespace) -> int:
    parsed = parse_portable_executable_from_path(args.file)
    if args.json:
        _json_success(
            CommandId.PE_IMPORTS,
            {
                "file": str(pathlib.Path(args.file).resolve()),
                "format": parsed.format,
                "count": len(parsed.imports),
                "imports": [_import_to_json(item) for item in parsed.imports],
            },
        )
        return ExitCodeMapper.SUCCESS

    if not parsed.imports:
        print("no imports found")
        return ExitCodeMapper.SUCCESS

    for item in parsed.imports:
        symbol = item.name if item.name is not None else f"ordinal:{item.ordinal}"
        hint = f"{item.hint}" if item.hint is not None else "-"
        print(
            f"{item.dll:<20} {symbol:<32} hint={hint:<5} thunk_rva=0x{item.thunk_rva:08x} iat_rva=0x{item.iat_rva:08x}"
        )
    return ExitCodeMapper.SUCCESS


def _conversion_result(file: str, section: PESection | None, **values: object) -> dict[str, object]:
    payload = {"file": str(pathlib.Path(file).resolve()), **values}
    if section is not None:
        payload["section"] = section.name
    else:
        payload["section"] = None
    return payload


def _cmd_pe_rva_to_file(args: argparse.Namespace) -> int:
    parsed = parse_portable_executable_from_path(args.file)
    rva = _parse_int(args.rva)
    file_offset, section = rva_to_file_offset(rva, parsed.sections)
    result = _conversion_result(
        args.file,
        section,
        rva=rva,
        rva_hex=f"0x{rva:08x}",
        file_offset=file_offset,
        file_offset_hex=f"0x{file_offset:08x}",
    )
    if args.json:
        _json_success(CommandId.PE_RVA_TO_FILE, result)
    else:
        print(f"rva=0x{rva:08x} -> file=0x{file_offset:08x} section={result['section']}")
    return ExitCodeMapper.SUCCESS


def _cmd_pe_file_to_rva(args: argparse.Namespace) -> int:
    parsed = parse_portable_executable_from_path(args.file)
    file_offset = _parse_int(args.offset)
    rva, section = file_offset_to_rva(file_offset, parsed.sections)
    result = _conversion_result(
        args.file,
        section,
        file_offset=file_offset,
        file_offset_hex=f"0x{file_offset:08x}",
        rva=rva,
        rva_hex=f"0x{rva:08x}",
    )
    if args.json:
        _json_success(CommandId.PE_FILE_TO_RVA, result)
    else:
        print(f"file=0x{file_offset:08x} -> rva=0x{rva:08x} section={result['section']}")
    return ExitCodeMapper.SUCCESS


def _cmd_pe_rva_to_va(args: argparse.Namespace) -> int:
    parsed = parse_portable_executable_from_path(args.file)
    rva = _parse_int(args.rva)
    section = find_section_for_rva(rva, parsed.sections)
    va = parsed.image_base + rva
    result = _conversion_result(
        args.file,
        section,
        image_base=parsed.image_base,
        image_base_hex=f"0x{parsed.image_base:x}",
        rva=rva,
        rva_hex=f"0x{rva:08x}",
        va=va,
        va_hex=f"0x{va:x}",
    )
    if args.json:
        _json_success(CommandId.PE_RVA_TO_VA, result)
    else:
        print(f"rva=0x{rva:08x} -> va=0x{va:x} section={result['section']}")
    return ExitCodeMapper.SUCCESS


def _cmd_pe_va_to_rva(args: argparse.Namespace) -> int:
    parsed = parse_portable_executable_from_path(args.file)
    va = _parse_int(args.va)
    if va < parsed.image_base:
        raise ShellforgeError(
            ErrorCode.INVALID_RVA,
            "VA is below image base",
            details={"va": f"0x{va:x}", "image_base": f"0x{parsed.image_base:x}"},
        )
    rva = va - parsed.image_base
    section = find_section_for_rva(rva, parsed.sections)
    result = _conversion_result(
        args.file,
        section,
        image_base=parsed.image_base,
        image_base_hex=f"0x{parsed.image_base:x}",
        va=va,
        va_hex=f"0x{va:x}",
        rva=rva,
        rva_hex=f"0x{rva:08x}",
    )
    if args.json:
        _json_success(CommandId.PE_VA_TO_RVA, result)
    else:
        print(f"va=0x{va:x} -> rva=0x{rva:08x} section={result['section']}")
    return ExitCodeMapper.SUCCESS


def _cmd_disasm(args: argparse.Namespace) -> int:
    payload = _read_bytes(args.file)
    base = _parse_int(args.base)
    result = disassemble_bytes(payload, arch=args.arch, base=base)

    if args.json:
        _json_success(
            CommandId.DISASM_ANALYZE,
            {
                "file": str(pathlib.Path(args.file).resolve()),
                "arch": result.arch,
                "base": result.base,
                "base_hex": f"0x{result.base:x}",
                "instruction_count": len(result.instructions),
                "metadata": {
                    "entropy": round(result.metadata.entropy, 6),
                    "printable_ratio": round(result.metadata.printable_ratio, 6),
                    "null_byte_count": result.metadata.null_byte_count,
                    "size": result.metadata.size,
                },
                "instructions": [
                    {
                        "address": item.address,
                        "address_hex": f"0x{item.address:x}",
                        "bytes": item.bytes_hex,
                        "mnemonic": item.mnemonic,
                        "operands": item.operands,
                    }
                    for item in result.instructions
                ],
            },
        )
        return ExitCodeMapper.SUCCESS

    print(
        f"arch={result.arch} base=0x{result.base:x} size={result.metadata.size} "
        f"instructions={len(result.instructions)} entropy={result.metadata.entropy:.4f} "
        f"printable_ratio={result.metadata.printable_ratio:.4f} null_bytes={result.metadata.null_byte_count}"
    )
    print("address      bytes                mnemonic      operands")
    print("-----------  -------------------  ------------  ------------------------------")
    for item in result.instructions:
        print(f"0x{item.address:08x}  {item.bytes_hex:<19}  {item.mnemonic:<12}  {item.operands}")
    return ExitCodeMapper.SUCCESS


def _cmd_analyze(args: argparse.Namespace) -> int:
    if args.window <= 0 or args.step <= 0:
        raise ValueError("--window and --step must be positive integers")
    if args.strings_min_len <= 0:
        raise ValueError("--strings-min-len must be a positive integer")
    if args.max_strings <= 0:
        raise ValueError("--max-strings must be a positive integer")
    if args.max_hits <= 0:
        raise ValueError("--max-hits must be a positive integer")
    hash_cross_reference = _build_hash_cross_reference_from_pe(args.hash_db, args.hash_algorithm)
    payload = _read_bytes(args.file)
    report = analyze_bytes(
        payload,
        arch=args.arch,
        window=args.window,
        step=args.step,
        strings_min_len=args.strings_min_len,
        max_strings=args.max_strings,
        max_hits=args.max_hits,
        hash_cross_reference=hash_cross_reference,
    )
    def _match_row(item) -> dict[str, object]:
        return {"offset": item.offset, "kind": item.kind, "detail": item.detail}

    if args.summary_only:
        top_heuristics = [
            {"name": str(item["name"]), "confidence": float(item["confidence"])}
            for item in report.heuristics
            if bool(item["matched"])
        ][:5]
        summary_payload = {
            "file": str(pathlib.Path(args.file).resolve()),
            "size": report.size,
            "detected_arch": report.detected_arch,
            "detection_confidence": report.detection_confidence,
            "entropy": round(report.entropy, 6),
            "printable_ratio": round(report.printable_ratio, 6),
            "null_byte_count": report.null_byte_count,
            "heuristic_hits": sum(1 for item in report.heuristics if item["matched"]),
            "likely_decoder": "xor" if any(item["name"] == "decoder_loop" and item["matched"] for item in report.heuristics) else "unknown",
            "top_heuristics": top_heuristics,
            "hash_cross_reference_hits": len(report.api_hash_cross_references),
        }
        if args.json:
            _json_success(CommandId.ANALYZE_STATIC, summary_payload)
        else:
            print(
                f"arch={report.detected_arch} confidence={report.detection_confidence:.2f} entropy={report.entropy:.4f} "
                f"printable_ratio={report.printable_ratio:.4f} null_bytes={report.null_byte_count} "
                f"heuristic_hits={summary_payload['heuristic_hits']} likely_decoder={summary_payload['likely_decoder']} "
                f"hash_xrefs={summary_payload['hash_cross_reference_hits']}"
            )
        return ExitCodeMapper.SUCCESS

    if args.json:
        _json_success(
            CommandId.ANALYZE_STATIC,
            {
                "file": str(pathlib.Path(args.file).resolve()),
                "detected_arch": report.detected_arch,
                "detection_confidence": report.detection_confidence,
                "size": report.size,
                "metadata": {
                    "entropy": round(report.entropy, 6),
                    "printable_ratio": round(report.printable_ratio, 6),
                    "null_byte_count": report.null_byte_count,
                },
                "heuristics": report.heuristics,
                "peb_walk_signatures": [_match_row(item) for item in report.peb_walk_signatures],
                "segment_access_signatures": [_match_row(item) for item in report.segment_access_signatures],
                "egg_markers": [_match_row(item) for item in report.egg_markers],
                "nop_regions": [_match_row(item) for item in report.nop_sleds],
                "decoder_loop_signatures": [_match_row(item) for item in report.decoder_loop_signatures],
                "hash_candidates": [_match_row(item) for item in report.api_hash_constants],
                "hash_cross_references": report.api_hash_cross_references,
                "hash_db_files": [str(pathlib.Path(item).resolve()) for item in args.hash_db],
                "hash_algorithm": args.hash_algorithm,
                "entropy_profile": report.entropy_windows,
                "strings": report.printable_strings,
                "strings_min_len": args.strings_min_len,
                "max_strings": args.max_strings,
                "strings_truncated": report.strings_truncated,
                "max_hits": args.max_hits,
                "summary_only": False,
            },
        )
        return ExitCodeMapper.SUCCESS

    print(
        f"arch={report.detected_arch} confidence={report.detection_confidence:.2f} size={report.size} entropy={report.entropy:.4f} printable_ratio={report.printable_ratio:.4f} "
        f"null_bytes={report.null_byte_count}"
    )
    print(
        "hits: "
        f"peb={len(report.peb_walk_signatures)} "
        f"segment={len(report.segment_access_signatures)} "
        f"egg={len(report.egg_markers)} "
        f"nop_sled={len(report.nop_sleds)} "
        f"decoder={len(report.decoder_loop_signatures)} "
        f"api_hash={len(report.api_hash_constants)} "
        f"hash_xref={len(report.api_hash_cross_references)}"
    )
    print(
        f"windows={len(report.entropy_windows)} window={args.window} step={args.step} "
        f"strings={len(report.printable_strings)} max_strings={args.max_strings} truncated={report.strings_truncated} max_hits={args.max_hits}"
    )
    for title, items in (
        ("PEB Walk", report.peb_walk_signatures),
        ("Segment Access", report.segment_access_signatures),
        ("Egg Markers", report.egg_markers),
        ("NOP Sleds", report.nop_sleds),
        ("Decoder Loops", report.decoder_loop_signatures),
        ("API Hash Constants", report.api_hash_constants),
    ):
        if not items:
            continue
        print(f"[{title}]")
        for item in items[:10]:
            print(f"  +0x{item.offset:04x} {item.detail}")
    if report.api_hash_cross_references:
        print("[Hash Cross-References]")
        for item in report.api_hash_cross_references[:10]:
            joined = ", ".join(item["matches"][:5])
            print(f"  +0x{item['offset']:04x} {item['hash_hex']} -> {joined}")
    if report.printable_strings:
        print("[Printable Strings]")
        for text in report.printable_strings[:10]:
            print(f"  {text}")
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

    pe_imports = pe_sub.add_parser("imports", help="List imported DLL symbols from a PE file")
    pe_imports.add_argument("file")
    pe_imports.add_argument("--json", action="store_true", help="emit JSON")
    pe_imports.set_defaults(handler=_cmd_pe_imports)

    pe_rva_to_file = pe_sub.add_parser("rva-to-file", help="Convert RVA to file offset")
    pe_rva_to_file.add_argument("file")
    pe_rva_to_file.add_argument("rva")
    pe_rva_to_file.add_argument("--json", action="store_true", help="emit JSON")
    pe_rva_to_file.set_defaults(handler=_cmd_pe_rva_to_file)

    pe_file_to_rva = pe_sub.add_parser("file-to-rva", help="Convert file offset to RVA")
    pe_file_to_rva.add_argument("file")
    pe_file_to_rva.add_argument("offset")
    pe_file_to_rva.add_argument("--json", action="store_true", help="emit JSON")
    pe_file_to_rva.set_defaults(handler=_cmd_pe_file_to_rva)

    pe_rva_to_va = pe_sub.add_parser("rva-to-va", help="Convert RVA to VA")
    pe_rva_to_va.add_argument("file")
    pe_rva_to_va.add_argument("rva")
    pe_rva_to_va.add_argument("--json", action="store_true", help="emit JSON")
    pe_rva_to_va.set_defaults(handler=_cmd_pe_rva_to_va)

    pe_va_to_rva = pe_sub.add_parser("va-to-rva", help="Convert VA to RVA")
    pe_va_to_rva.add_argument("file")
    pe_va_to_rva.add_argument("va")
    pe_va_to_rva.add_argument("--json", action="store_true", help="emit JSON")
    pe_va_to_rva.set_defaults(handler=_cmd_pe_va_to_rva)

    disasm_cmd = sub.add_parser("disasm", help="Offline disassembly analysis")
    disasm_cmd.add_argument("file")
    disasm_cmd.add_argument("--arch", default="x86", choices=["x86", "x64"])
    disasm_cmd.add_argument("--base", default="0x0", help="base address (hex or decimal)")
    disasm_cmd.add_argument("--json", action="store_true", help="emit JSON")
    disasm_cmd.set_defaults(handler=_cmd_disasm)

    analyze_cmd = sub.add_parser("analyze", help="Static shellcode-oriented byte analysis")
    analyze_cmd.add_argument("file")
    analyze_cmd.add_argument("--arch", default="auto", choices=["auto", "x86", "x64"])
    analyze_cmd.add_argument("--window", type=int, default=64)
    analyze_cmd.add_argument("--step", type=int, default=16)
    analyze_cmd.add_argument("--strings-min-len", type=int, default=4)
    analyze_cmd.add_argument("--max-strings", type=int, default=50)
    analyze_cmd.add_argument("--max-hits", type=int, default=25)
    analyze_cmd.add_argument("--hash-db", action="append", default=[], help="PE file used for hash cross-reference")
    analyze_cmd.add_argument("--hash-algorithm", default="ror13", choices=sorted(HASHERS.keys()))
    analyze_cmd.add_argument("--summary-only", action="store_true")
    analyze_cmd.add_argument("--json", action="store_true", help="emit JSON")
    analyze_cmd.set_defaults(handler=_cmd_analyze)

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


def _build_hash_cross_reference_from_pe(hash_db_files: list[str], hash_algorithm: str) -> dict[int, list[str]] | None:
    if not hash_db_files:
        return None
    hasher = HASHERS[hash_algorithm]
    merged: dict[int, list[str]] = {}
    for file_path in hash_db_files:
        parsed = parse_portable_executable_from_path(file_path)
        namespace = pathlib.Path(file_path).name
        symbols = [item.name for item in parsed.exports if item.name]
        rows = build_hash_cross_reference(symbols, hasher, namespace=namespace)
        for value, labels in rows.items():
            merged.setdefault(value, []).extend(labels)
    for value in list(merged.keys()):
        merged[value] = sorted(set(merged[value]))
    return merged


if __name__ == "__main__":
    raise SystemExit(main())
