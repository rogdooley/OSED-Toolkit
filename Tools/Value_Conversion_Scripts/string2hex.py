#!/usr/bin/env python3

from __future__ import annotations

import socket
import struct
import sys
from pathlib import Path


SCRIPT_DIR = str(Path(__file__).resolve().parent)
if SCRIPT_DIR in sys.path:
    sys.path.remove(SCRIPT_DIR)

import argparse
from typing import Iterable, NamedTuple


class Chunk(NamedTuple):
    index: int
    raw: bytes
    padded: bytes
    little_endian_hex: str

    @property
    def contains_null(self) -> bool:
        return b"\x00" in self.padded


def chunk_bytes(data: bytes, chunk_size: int) -> list[Chunk]:
    if chunk_size <= 0:
        raise ValueError("chunk_size must be greater than zero")

    chunks: list[Chunk] = []
    for index in range(0, len(data), chunk_size):
        raw = data[index : index + chunk_size]
        padded = raw.ljust(chunk_size, b"\x00")
        chunks.append(
            Chunk(
                index=index // chunk_size,
                raw=raw,
                padded=padded,
                little_endian_hex=f"0x{padded[::-1].hex()}",
            )
        )

    if not chunks:
        padded = b"\x00" * chunk_size
        chunks.append(
            Chunk(
                index=0,
                raw=b"",
                padded=padded,
                little_endian_hex=f"0x{padded[::-1].hex()}",
            )
        )

    return chunks


def format_chunks(text: str, encoding: str = "utf-8", chunk_size: int = 4) -> list[Chunk]:
    data = text.encode(encoding)
    return chunk_bytes(data, chunk_size)


def format_wide_chunks(text: str, chunk_size: int = 4) -> list[Chunk]:
    return chunk_bytes(text.encode("utf-16le"), chunk_size)


def format_push(chunk: Chunk, architecture: str) -> list[str]:
    if architecture == "x64":
        return [f"mov rax, {chunk.little_endian_hex}", "push rax"]
    return [f"push {chunk.little_endian_hex}"]


def format_ip(ip_address: str) -> str:
    packed_ip = socket.inet_aton(ip_address)
    value = struct.unpack("<I", packed_ip)[0]
    return f"0x{value:08x}"


def mitigation_notes(chunks: Iterable[Chunk]) -> list[str]:
    chunks = list(chunks)
    notes: list[str] = []

    if any(chunk.contains_null for chunk in chunks):
        notes.append(
            "Null bytes detected in one or more output chunks. If the issue is only padding, shorten the final write or handle the tail separately."
        )
        notes.append(
            "For embedded zero bytes in the source data, use a runtime reconstruction strategy instead of direct immediates: split into smaller writes, decode with XOR/add/sub at runtime, or write through registers into memory."
        )
        notes.append(
            "On x86/x64 Windows, avoid zero-containing immediates in the instruction stream. Prefer non-zero constants plus arithmetic, then store the result to the destination buffer."
        )
    else:
        notes.append("No null bytes were introduced by the chosen chunking and padding.")

    return notes


def build_output(
    text: str,
    encoding: str = "utf-8",
    chunk_size: int = 4,
    *,
    architecture: str = "x86",
    output_mode: str = "both",
    string_format: str = "ascii",
) -> str:
    chunks = format_wide_chunks(text, chunk_size=chunk_size) if string_format == "wide" else format_chunks(text, encoding=encoding, chunk_size=chunk_size)
    return render_string_output(
        text,
        chunks=chunks,
        encoding=encoding,
        chunk_size=chunk_size,
        architecture=architecture,
        output_mode=output_mode,
        string_format=string_format,
    )


def build_string_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> argparse.ArgumentParser:
    parser = subparsers.add_parser(
        "string",
        help="Convert one or more strings into little-endian hex chunks",
    )
    parser.add_argument("texts", nargs="*", help="String(s) to convert")
    parser.add_argument(
        "-f",
        "--file",
        dest="input_file",
        help="Read one string per line from a file",
    )
    parser.add_argument(
        "-e",
        "--encoding",
        default="utf-8",
        help="Text encoding used before chunking in ASCII mode (default: utf-8)",
    )
    parser.add_argument(
        "-c",
        "--chunk-size",
        type=int,
        default=4,
        help="Chunk size in bytes (default: 4)",
    )
    parser.add_argument(
        "--arch",
        choices=("x86", "x64"),
        default="x86",
        help="Assembly style used for push output (default: x86)",
    )
    parser.add_argument(
        "--format",
        choices=("hex", "push", "both"),
        default="both",
        help="Select hex, assembly, or both outputs (default: both)",
    )
    parser.add_argument(
        "--string-format",
        choices=("ascii", "wide"),
        default="ascii",
        help="Interpret strings as ASCII bytes or UTF-16LE Windows wide strings (default: ascii)",
    )
    parser.set_defaults(command="string")
    return parser


def build_ip_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> argparse.ArgumentParser:
    parser = subparsers.add_parser(
        "ip",
        help="Convert IPv4 addresses into little-endian hex values",
    )
    parser.add_argument("ips", nargs="*", help="IPv4 address(es) to convert")
    parser.add_argument(
        "-f",
        "--file",
        dest="input_file",
        help="Read one IPv4 address per line from a file",
    )
    parser.add_argument(
        "--format",
        choices=("hex", "push", "both"),
        default="both",
        help="Select hex, assembly, or both outputs (default: both)",
    )
    parser.set_defaults(command="ip")
    return parser


def parse_args(argv: list[str]) -> argparse.Namespace:
    normalized_argv = list(argv)
    if normalized_argv and normalized_argv[0] not in {"string", "ip", "-h", "--help"}:
        normalized_argv = ["string", *normalized_argv]

    parser = argparse.ArgumentParser(
        description="Convert strings or IPv4 addresses into little-endian hex values for shellcode workflows."
    )
    subparsers = parser.add_subparsers(dest="command")
    build_string_parser(subparsers)
    build_ip_parser(subparsers)

    args = parser.parse_args(normalized_argv)
    if not getattr(args, "command", None):
        parser.error("specify 'string' or 'ip'")
    return args


def load_inputs(args: argparse.Namespace) -> list[str]:
    texts = list(args.texts)
    if args.input_file:
        path = Path(args.input_file)
        file_text = path.read_text(encoding=args.encoding)
        texts.extend(line for line in file_text.splitlines() if line.strip())
    if not texts:
        raise ValueError("provide at least one string argument or use --file")
    return texts


def load_ip_inputs(args: argparse.Namespace) -> list[str]:
    ips = list(args.ips)
    if args.input_file:
        path = Path(args.input_file)
        file_text = path.read_text(encoding="utf-8")
        ips.extend(line for line in file_text.splitlines() if line.strip())
    if not ips:
        raise ValueError("provide at least one IPv4 address or use --file")
    return ips


def render_inputs(
    texts: list[str],
    *,
    encoding: str,
    chunk_size: int,
    architecture: str,
    output_mode: str,
    string_format: str = "ascii",
) -> str:
    sections: list[str] = []
    for index, text in enumerate(texts, start=1):
        chunks = format_wide_chunks(text, chunk_size=chunk_size) if string_format == "wide" else format_chunks(text, encoding=encoding, chunk_size=chunk_size)
        if len(texts) == 1:
            sections.append(
                render_string_output(
                    text,
                    chunks=chunks,
                    encoding=encoding,
                    chunk_size=chunk_size,
                    architecture=architecture,
                    output_mode=output_mode,
                    string_format=string_format,
                )
            )
            continue

        sections.append(
            "\n".join(
                [
                    f"Item {index}/{len(texts)}",
                    render_string_output(
                        text,
                        chunks=chunks,
                        encoding=encoding,
                        chunk_size=chunk_size,
                        architecture=architecture,
                        output_mode=output_mode,
                        string_format=string_format,
                    ),
                ]
            )
        )

    return "\n\n".join(sections)


def render_string_output(
    text: str,
    *,
    chunks: list[Chunk],
    encoding: str,
    chunk_size: int,
    architecture: str,
    output_mode: str,
    string_format: str,
) -> str:
    lines = [
        f"Input: {text!r}",
        f"Encoding: {encoding if string_format == 'ascii' else 'utf-16le'}",
        f"String format: {string_format}",
        f"Chunk size: {chunk_size} byte(s)",
        f"Architecture: {architecture}",
        "",
    ]
    if output_mode in {"hex", "both"}:
        lines.append("Little-endian chunks:")

        for chunk in chunks:
            ascii_preview = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk.raw)
            lines.append(f"  {chunk.little_endian_hex}  ; chunk {chunk.index} raw={chunk.raw.hex()} ascii={ascii_preview!r}")
        lines.append("")

    if output_mode in {"push", "both"}:
        lines.append("Assembly:")
        for chunk in chunks:
            ascii_preview = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk.raw)
            lines.append(f"  ; chunk {chunk.index} raw={chunk.raw.hex()} ascii={ascii_preview!r}")
            for instruction in format_push(chunk, architecture):
                lines.append(f"  {instruction}")
        lines.append("")

    lines.append("Mitigations:")
    if string_format == "wide":
        lines.append("  - Wide strings use UTF-16LE and intentionally include 0x00 bytes between ASCII characters.")
    for note in mitigation_notes(chunks):
        lines.append(f"  - {note}")

    return "\n".join(lines)


def render_ip_inputs(ips: list[str], output_mode: str) -> str:
    sections: list[str] = []
    for index, ip_address in enumerate(ips, start=1):
        hex_value = format_ip(ip_address)
        lines = [
            f"Input: {ip_address}",
            "Format: IPv4",
        ]
        if output_mode in {"hex", "both"}:
            lines.append(f"Little-endian hex: {hex_value}")
        if output_mode in {"push", "both"}:
            lines.append("Assembly:")
            lines.append(f"  push {hex_value}")
        if len(ips) > 1:
            sections.append("\n".join([f"Item {index}/{len(ips)}", *lines]))
        else:
            sections.append("\n".join(lines))
    return "\n\n".join(sections)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        if args.command == "ip":
            ips = load_ip_inputs(args)
            print(render_ip_inputs(ips, output_mode=args.format))
        else:
            texts = load_inputs(args)
            print(
                render_inputs(
                    texts,
                    encoding=args.encoding,
                    chunk_size=args.chunk_size,
                    architecture=args.arch,
                    output_mode=args.format,
                    string_format=args.string_format,
                )
            )
    except UnicodeEncodeError as exc:
        print(f"Encoding error: {exc}", file=sys.stderr)
        return 1
    except (socket.error, OSError, ValueError) as exc:
        print(f"Invalid argument: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
