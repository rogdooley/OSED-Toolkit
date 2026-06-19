#!/usr/bin/env python3
"""
Single-shot bad-char verdict from one captured dump (mona !cmp equivalent).

Use this when the target mangles bytes *in place* rather than truncating the
copy — e.g. Vulnserver LTER, which ASCII-folds every byte >= 0x80. The
orchestrator's iterative exclude-and-resend model needs one iteration per bad
char and cannot express a systematic transform; this reads the entire verdict
from a single positionally-aligned dump.

Workflow:
    1. Capture one dump containing [MAGIC][candidate bytes] in the destination
       (the same dump the orchestrator polls, or a manual .writemem).
    2. Run this against that dump with the same magic and exclusions you used
       to build the candidate array.

Example:
    py compare_dump.py --dump C:/dbg/dump.bin --magic bcf0bcf0 --exclude 00,0a,0d
"""

import argparse
import os
import sys

_THIS_DIR = os.path.abspath(os.path.dirname(__file__))
_TOOLS_DIR = os.path.abspath(os.path.join(_THIS_DIR, ".."))
if _TOOLS_DIR not in sys.path:
    sys.path.insert(0, _TOOLS_DIR)

from badchars_wds.analyzer import full_compare, generate_candidate_bytes


def _parse_excluded(text):
    # type: (str) -> set
    if not text:
        return set()
    out = set()
    for token in text.replace(" ", "").split(","):
        if not token:
            continue
        out.add(int(token, 16))
    return out


def _parse_magic(text):
    # type: (str) -> bytes
    cleaned = text.strip().lower()
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    return bytes.fromhex(cleaned)


def _fmt_bytes(values):
    # type: (list) -> str
    return " ".join("{:02x}".format(v) for v in values)


def _print_table(comparison):
    # type: (...) -> None
    """Render an aligned File-vs-Memory table in mona's 16-per-row layout."""
    verdicts = comparison.verdicts
    print("    ,-----------------------------------------------.")
    for row_start in range(0, len(verdicts), 16):
        row = verdicts[row_start:row_start + 16]
        sent = " ".join("{:02x}".format(v.sent) for v in row)
        mem = " ".join(
            "  " if v.observed is None else "{:02x}".format(v.observed)
            for v in row
        )
        print("{:>3x} |{:<47}| File".format(row_start, sent))
        print("    |{:<47}| Memory".format(mem))
    print("    `-----------------------------------------------'")


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dump", required=True, help="Path to the captured dump file.")
    parser.add_argument("--magic", default="bcf0bcf0",
                        help="Magic prefix (hex) that precedes the candidates. Default bcf0bcf0.")
    parser.add_argument("--exclude", default="00,0a,0d",
                        help="Comma-separated hex bytes excluded from the candidate array.")
    parser.add_argument("--no-magic", action="store_true",
                        help="The dump has no magic prefix; compare from byte 0.")
    parser.add_argument("--table", action="store_true",
                        help="Print the full File-vs-Memory comparison table.")
    parser.add_argument("--allow-short", action="store_true",
                        help="Proceed even if the observation is shorter than the "
                             "candidate set (normally a truncation signature that "
                             "this tool is the wrong choice for).")
    args = parser.parse_args()

    with open(args.dump, "rb") as fh:
        data = fh.read()

    # Alignment gate: full_compare() is only meaningful when the observation is
    # positionally aligned to the candidate array. A wrong magic means the
    # breakpoint/dump_expr points at the wrong address, so refuse rather than
    # classify garbage.
    if not args.no_magic:
        magic = _parse_magic(args.magic)
        if data[:len(magic)] != magic:
            print("ERROR: magic {} not found at start of dump (found {}). "
                  "Wrong dump_expr/breakpoint, or pass --no-magic.".format(
                      magic.hex(), data[:len(magic)].hex()), file=sys.stderr)
            return 2
        observed = data[len(magic):]
    else:
        observed = data

    excluded = _parse_excluded(args.exclude)
    expected = generate_candidate_bytes(excluded)

    # Length gate: an observation shorter than the candidate set means bytes
    # were dropped — the truncation signature. full_compare() would report a
    # long "missing" tail that looks like a transform but is not. Refuse unless
    # the operator explicitly overrides, and point at the right tool.
    if len(observed) < len(expected) and not args.allow_short:
        print("ERROR: observation is {} bytes but the candidate set is {} "
              "bytes — the dump is truncated or misaligned.".format(
                  len(observed), len(expected)), file=sys.stderr)
        print("       This is the signature of a TRUNCATING bad char (a byte "
              "that ends the copy), which full_compare() cannot classify "
              "correctly. Use the iterative run_badchars.py for this target, "
              "or pass --allow-short if you are certain the dump is aligned and "
              "intentionally short.", file=sys.stderr)
        return 3

    comparison = full_compare(expected, observed)

    if args.table:
        _print_table(comparison)
        print()

    # Observability: surface the alignment facts the conclusion rests on.
    print("[+] expected candidates : {}".format(comparison.expected_len))
    print("[+] observed (post-magic): {}".format(comparison.observed_len))
    print("[+] aligned/compared     : {}".format(comparison.aligned_len))
    if comparison.first_mismatch_offset is not None:
        fm = comparison.first_mismatch_offset
        print("[+] first mismatch offset: {} (sent 0x{:02x})".format(
            fm, comparison.verdicts[fm].sent))
    print("[+] preserved {}, transformed {}, missing {}".format(
        len(comparison.allowed_bytes),
        len(comparison.transformed_bytes),
        len(comparison.missing_bytes)))

    if comparison.detected_transform:
        print("[!] {}".format(comparison.detected_transform))
    elif comparison.transformed_bytes:
        print("[!] mismatches do not fit a known systematic transform — treat "
              "the transformed list as discrete byte constraints.")

    print()
    print("Allowed charset    : {}".format(
        _fmt_bytes(comparison.allowed_bytes) or "(none)"))
    print("Transformed bytes  : {}".format(
        _fmt_bytes(comparison.transformed_bytes) or "(none)"))
    print("Missing bytes      : {}".format(
        _fmt_bytes(comparison.missing_bytes) or "(none)"))
    print("Unusable (do not use in shellcode): {}".format(
        _fmt_bytes(comparison.unusable_bytes) or "(none)"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
