#!/usr/bin/env python3

from __future__ import annotations

import socket
import struct
import sys
import subprocess
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


def format_port(port: int) -> tuple[str, str]:
    if not (1 <= port <= 65535):
        raise ValueError("port must be in the range 1..65535")

    network_value = socket.htons(port)
    return f"0x{network_value:04x}", f"0x{port:04x}"


def detect_current_ipv4() -> str:
    try:
        result = subprocess.run(
            ["ip", "-o", "-4", "route", "get", "1.1.1.1"],
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:
        raise ValueError("current IP detection requires the `ip` command to be available") from exc
    except subprocess.CalledProcessError:
        result = None

    if result is not None:
        tokens = result.stdout.split()
        if "src" in tokens:
            src_index = tokens.index("src")
            if src_index + 1 < len(tokens):
                return tokens[src_index + 1]

    try:
        result = subprocess.run(
            ["hostname", "-I"],
            check=True,
            capture_output=True,
            text=True,
        )
        candidates = [token.strip() for token in result.stdout.split() if token.strip()]
        for ip_address in candidates:
            if not ip_address.startswith("127."):
                return ip_address
    except (FileNotFoundError, subprocess.CalledProcessError):
        pass

    try:
        result = subprocess.run(
            ["ifconfig"],
            check=True,
            capture_output=True,
            text=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
        raise ValueError("unable to determine the current IPv4 address from routing or interface tools") from exc

    for line in result.stdout.splitlines():
        line = line.strip()
        if "inet " not in line or "127.0.0.1" in line:
            continue
        parts = line.split()
        for index, token in enumerate(parts):
            if token == "inet" and index + 1 < len(parts):
                return parts[index + 1]

    raise ValueError("unable to determine the current IPv4 address")


def detect_vpn_ipv4(preferred_interface: str | None = None) -> str:
    try:
        if preferred_interface:
            cmd = ["ip", "-o", "-4", "addr", "show", "dev", preferred_interface]
        else:
            cmd = ["ip", "-o", "-4", "addr", "show", "up"]
        result = subprocess.run(
            cmd,
            check=True,
            capture_output=True,
            text=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        result = None

    if result is None:
        try:
            result = subprocess.run(
                ["ifconfig"],
                check=True,
                capture_output=True,
                text=True,
            )
        except (FileNotFoundError, subprocess.CalledProcessError) as exc:
            raise ValueError("unable to enumerate IPv4 interfaces for vpn detection") from exc

        current_iface = None
        candidates: list[tuple[int, str, str]] = []
        for line in result.stdout.splitlines():
            if not line or not line[0].isspace():
                current_iface = line.split(":", 1)[0].strip()
                continue
            stripped = line.strip()
            if "inet " not in stripped:
                continue
            if current_iface is None:
                continue
            parts = stripped.split()
            try:
                ip_address = parts[parts.index("inet") + 1]
            except (ValueError, IndexError):
                continue
            if ip_address.startswith("127."):
                continue
            priority = -1 if preferred_interface and current_iface == preferred_interface else 0
            if any(token in current_iface.lower() for token in ("tun", "tap", "vpn", "wg", "ppp")):
                priority = min(priority, 0)
            candidates.append((priority, current_iface, ip_address))

        if not candidates:
            raise ValueError("no non-loopback IPv4 interface found for vpn detection; try a literal IP instead")

        candidates.sort(key=lambda item: (item[0], item[1]))
        return candidates[0][2]

    candidates: list[tuple[int, str, str]] = []
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        iface = parts[1]
        ip_cidr = parts[3]
        ip_address = ip_cidr.split("/", 1)[0]
        if ip_address.startswith("127."):
            continue
        priority = 1
        lowered = iface.lower()
        if preferred_interface and iface == preferred_interface:
            priority = -1
        elif any(token in lowered for token in ("tun", "tap", "vpn", "wg", "ppp")):
            priority = 0
        candidates.append((priority, iface, ip_address))

    if not candidates:
        raise ValueError("no non-loopback IPv4 interface found for vpn detection; try a literal IP instead")

    candidates.sort(key=lambda item: (item[0], item[1]))
    return candidates[0][2]


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
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("ips", nargs="*", metavar="IP", help="IPv4 address(es) to convert")
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
        help="Select hex, assembly, or both outputs",
    )
    parser.set_defaults(command="ip")
    return parser


def build_sockaddr_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> argparse.ArgumentParser:
    parser = subparsers.add_parser(
        "sockaddr",
        help="Convert an IPv4 address and port into sockaddr_in fields",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    source = parser.add_mutually_exclusive_group(required=False)
    source.add_argument("--ip", metavar="IP", help="IPv4 address to encode")
    source.add_argument("--current", action="store_true", help="Use the machine's primary non-loopback IPv4 address")
    source.add_argument("--vpn", action="store_true", help="Use a VPN-style interface IPv4 address")
    parser.add_argument(
        "--port",
        type=int,
        metavar="PORT",
        help="TCP/UDP port to encode",
    )
    parser.add_argument(
        "--interface",
        metavar="IFACE",
        help="Preferred interface name for vpn lookup, such as tun0 or wg0",
    )
    parser.add_argument(
        "legacy",
        nargs="*",
        metavar="LEGACY",
        help=argparse.SUPPRESS,
    )
    parser.set_defaults(command="sockaddr")
    return parser


def parse_args(argv: list[str]) -> argparse.Namespace:
    normalized_argv = list(argv)
    if normalized_argv and normalized_argv[0] not in {"string", "ip", "sockaddr", "-h", "--help"}:
        normalized_argv = ["string", *normalized_argv]

    parser = argparse.ArgumentParser(
        description="Convert strings, IPv4 addresses, and sockaddr_in fields into shellcode-friendly hex values.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", title="subcommands", metavar="{string,ip,sockaddr}")
    build_string_parser(subparsers)
    build_ip_parser(subparsers)
    build_sockaddr_parser(subparsers)

    args = parser.parse_args(normalized_argv)
    if not getattr(args, "command", None):
        parser.error("specify one of: string, ip, sockaddr")
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


def render_sockaddr_input(ip_address: str, port: int) -> str:
    ip_hex = format_ip(ip_address)
    port_immediate_hex, port_value_hex = format_port(port)
    return "\n".join(
        [
            f"Input: {ip_address}:{port}",
            "Format: sockaddr_in",
            "Structure fields:",
            "  sin_family = 0x0002",
            f"  sin_port   = {port_value_hex}  ; port number, encoded as {port_immediate_hex} for mov ax",
            f"  sin_addr   = {ip_hex}  ; little-endian DWORD for push/use in memory",
            "  sin_zero   = 0x0000000000000000",
            "",
            "Assembly-friendly values:",
            f"  port register value: {port_immediate_hex} (use with mov ax, ... before shifting)",
            f"  push dword for sin_addr: {ip_hex}",
        ]
    )


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        if args.command == "ip":
            ips = load_ip_inputs(args)
            print(render_ip_inputs(ips, output_mode=args.format))
        elif args.command == "sockaddr":
            ip_value = args.ip
            port_value = args.port

            if ip_value is None and port_value is None and len(args.legacy) == 2:
                ip_value, port_raw = args.legacy
                try:
                    port_value = int(port_raw)
                except ValueError as exc:
                    raise ValueError("legacy sockaddr form requires an integer port") from exc

            if port_value is None:
                raise ValueError("sockaddr requires --port")

            if args.current:
                ip_address, source = detect_current_ipv4(), "current"
            elif args.vpn:
                ip_address, source = detect_vpn_ipv4(args.interface), "vpn"
            elif args.interface:
                ip_address, source = detect_vpn_ipv4(args.interface), f"interface:{args.interface}"
            elif ip_value is not None:
                selector = ip_value.lower()
                if selector == "current":
                    ip_address, source = detect_current_ipv4(), "current"
                elif selector == "vpn":
                    ip_address, source = detect_vpn_ipv4(args.interface), "vpn"
                else:
                    ip_address, source = ip_value, "literal"
            else:
                raise ValueError("sockaddr requires --ip, --current, or --vpn")

            output = render_sockaddr_input(ip_address, port_value)
            if source != "literal":
                output = f"Resolved IP source: {source}\n{output}"
            print(output)
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
