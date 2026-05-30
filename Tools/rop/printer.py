"""
DryRunPrinter — human-readable annotated table of a symbolic ROP chain.

Output columns
--------------
IDX     chain entry index (PaddingBlock expands to count rows)
OFFSET  byte offset from chain start (+0x000, +0x004, …)
TYPE    element kind (gadget_ref, raw_dword, writable_ptr, …)
VALUE   packed little-endian value in hex, or '<dynamic>' for ShellcodePtr
SOURCE  "gadget_name @ module" or "(literal)" / "(runtime)"
PURPOSE human-readable annotation from the element's purpose field

Bad bytes are highlighted in red when the terminal supports ANSI codes.
Missing gadgets are highlighted in red regardless of bad_chars.
"""

from __future__ import annotations

import struct
import sys

from Tools.rop.gadget_db import GadgetDB
from Tools.rop.models import (
    ChainElement,
    GadgetRef,
    PaddingBlock,
    RawDword,
    ShellcodePtr,
    WritablePtr,
)

_RED   = "\033[31m"
_RESET = "\033[0m"

# Column widths
_W_IDX    = 4
_W_OFFSET = 7
_W_TYPE   = 18
_W_VALUE  = 10
_W_SOURCE = 32


def _use_color() -> bool:
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


class DryRunPrinter:
    """
    Pretty-print a symbolic ROP chain as an annotated table.

    Example::

        printer = DryRunPrinter()
        printer.print_chain(vp_chain.plan(), db, bad_chars=b"\\x00\\x0a\\x0d")
    """

    def print_chain(
        self,
        chain: list[ChainElement],
        db: GadgetDB,
        bad_chars: bytes = b"",
        *,
        use_color: bool | None = None,
    ) -> None:
        """
        Print the chain table to stdout.

        Parameters
        ----------
        chain:
            Symbolic element list from a planner or RopChain.elements().
        db:
            GadgetDB for resolving names to addresses.
        bad_chars:
            Bytes whose presence in a packed value triggers a red highlight.
        use_color:
            Force ANSI color on or off.  Defaults to auto-detect (tty check).
        """
        color = _use_color() if use_color is None else use_color
        bad_set = set(bad_chars)

        header = (
            f"{'IDX':>{_W_IDX}}  "
            f"{'OFFSET':>{_W_OFFSET}}  "
            f"{'TYPE':<{_W_TYPE}}  "
            f"{'VALUE':>{_W_VALUE}}  "
            f"{'SOURCE':<{_W_SOURCE}}  "
            f"PURPOSE"
        )
        sep = "-" * (len(header) + 4)
        print(header)
        print(sep)

        slot = 0
        offset = 0
        for elem in chain:
            rows = self._expand(elem, db, slot, offset)
            for row in rows:
                print(self._render(row, bad_set, color))
            slot += len(rows)
            offset += len(rows) * 4

        print(sep)
        print(f"Total: {slot} dwords, {offset} bytes")

    # ── Row production ────────────────────────────────────────────────────────

    def _expand(
        self,
        elem: ChainElement,
        db: GadgetDB,
        start_slot: int,
        start_offset: int,
    ) -> list[dict]:
        """Expand one ChainElement into one or more row dicts."""
        match elem:
            case RawDword(value=v, purpose=p):
                return [self._row(start_slot, start_offset,
                                  "raw_dword", v, f"{v:#010x}", "(literal)", p)]

            case GadgetRef(name=n, purpose=p):
                if db.contains(n):
                    g = db.get(n)
                    source = f"{n} @ {g.module}"
                    val = g.address
                    val_str = f"{val:#010x}"
                else:
                    source = f"{n} [MISSING]"
                    val = None
                    val_str = "?? MISSING ??"
                return [self._row(start_slot, start_offset,
                                  "gadget_ref", val, val_str, source, p)]

            case WritablePtr(name=n, purpose=p):
                if db.contains(n):
                    g = db.get(n)
                    source = f"{n} @ {g.module}"
                    val = g.address
                    val_str = f"{val:#010x}"
                else:
                    source = f"{n} [MISSING]"
                    val = None
                    val_str = "?? MISSING ??"
                return [self._row(start_slot, start_offset,
                                  "writable_ptr", val, val_str, source, p)]

            case ShellcodePtr(purpose=p):
                return [self._row(start_slot, start_offset,
                                  "shellcode_ptr", None, "<dynamic>", "(runtime)", p)]

            case PaddingBlock(count=c, value=v, purpose=p):
                rows = []
                for i in range(c):
                    rows.append(self._row(
                        start_slot + i,
                        start_offset + i * 4,
                        "padding",
                        v,
                        f"{v:#010x}",
                        "(filler)",
                        p if i == 0 else "",
                    ))
                return rows

        return [self._row(start_slot, start_offset,
                          "UNKNOWN", None, "???", "", "")]

    @staticmethod
    def _row(
        idx: int,
        offset: int,
        kind: str,
        value: int | None,
        value_str: str,
        source: str,
        purpose: str,
    ) -> dict:
        return {
            "idx": idx,
            "offset": offset,
            "kind": kind,
            "value": value,
            "value_str": value_str,
            "source": source,
            "purpose": purpose,
        }

    def _render(self, row: dict, bad_set: set[int], color: bool) -> str:
        idx       = row["idx"]
        offset    = row["offset"]
        kind      = row["kind"]
        value_str = row["value_str"]
        source    = row["source"]
        purpose   = row["purpose"]
        value     = row["value"]

        is_missing = "MISSING" in source
        is_bad = (
            value is not None
            and bad_set
            and any(b in bad_set for b in struct.pack("<I", value))
        )

        line = (
            f"[{idx:0{_W_IDX - 2}d}]"
            f"  +{offset:#0{_W_OFFSET - 1}x}"
            f"  {kind:<{_W_TYPE}}"
            f"  {value_str:>{_W_VALUE}}"
            f"  {source:<{_W_SOURCE}}"
            f"  {purpose}"
        )

        if color and (is_missing or is_bad):
            line = f"{_RED}{line}{_RESET}"
        return line
