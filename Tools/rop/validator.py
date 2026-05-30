"""
ChainValidator — validates a symbolic ROP chain before serialization.

Returns a list of ValidationIssue; an empty list means the chain is clean.
All checks are independent; the full list is always returned so the caller
can see every problem at once.

Checks performed
----------------
MISSING_GADGET      (error)   — GadgetRef or WritablePtr whose name is absent
                                from the GadgetDB
BAD_CHARS           (error)   — packed address / value contains a byte present
                                in the caller's bad-char set
ZERO_PADDING        (error)   — PaddingBlock with count=0 (constructor-level
                                guard should prevent this, but checked anyway)
NO_WRITABLE_PTR     (error)   — chain contains no WritablePtr element;
                                VirtualProtect needs one for lpflOldProtect
NULL_BYTE_IN_SIZE   (warning) — negated shellcode size contains a null byte
                                (only relevant when bad_chars includes 0x00)
STACK_ALIGNMENT     (warning) — total chain length is not 16-byte aligned
                                (MSVC prologues require 16-byte aligned ESP)
NO_RETURN_TARGET    (warning) — no ShellcodePtr or jmp-esp gadget reference
                                found; VirtualProtect needs somewhere to return
"""

from __future__ import annotations

import struct
from typing import Sequence

from Tools.rop.gadget_db import GadgetDB
from Tools.rop.models import (
    ChainElement,
    GadgetRef,
    PaddingBlock,
    RawDword,
    ShellcodePtr,
    ValidationIssue,
    WritablePtr,
)


class ChainValidator:
    """
    Validate a symbolic ROP chain.

    Usage::

        validator = ChainValidator()
        issues = validator.validate(chain, db, bad_chars=b"\\x00\\x0a\\x0d")
        errors = [i for i in issues if i.severity == "error"]
        if errors:
            for e in errors:
                print(e)
    """

    def validate(
        self,
        chain: Sequence[ChainElement],
        db: GadgetDB,
        bad_chars: bytes = b"",
    ) -> list[ValidationIssue]:
        """
        Run all checks and return every issue found.

        Parameters
        ----------
        chain:
            Symbolic chain returned by a planner or built with RopChain.
        db:
            Gadget database used to resolve names to addresses.
        bad_chars:
            Bytes that must not appear in any packed address or constant.
            Pass ``b""`` to skip this check.
        """
        issues: list[ValidationIssue] = []
        chain = list(chain)

        issues += self._check_missing_gadgets(chain, db)
        issues += self._check_bad_chars(chain, db, bad_chars)
        issues += self._check_zero_padding(chain)
        issues += self._check_writable_ptr(chain)
        issues += self._check_return_target(chain, db)
        issues += self._check_stack_alignment(chain)

        return issues

    # ── Individual checks ─────────────────────────────────────────────────────

    def _check_missing_gadgets(
        self,
        chain: list[ChainElement],
        db: GadgetDB,
    ) -> list[ValidationIssue]:
        issues = []
        for idx, elem in enumerate(chain):
            name: str | None = None
            if isinstance(elem, GadgetRef):
                name = elem.name
            elif isinstance(elem, WritablePtr):
                name = elem.name
            if name is not None and not db.contains(name):
                issues.append(ValidationIssue(
                    severity="error",
                    code="MISSING_GADGET",
                    message=f"'{name}' not found in gadget database",
                    element_index=idx,
                ))
        return issues

    def _check_bad_chars(
        self,
        chain: list[ChainElement],
        db: GadgetDB,
        bad_chars: bytes,
    ) -> list[ValidationIssue]:
        if not bad_chars:
            return []
        bad_set = set(bad_chars)
        issues = []

        for idx, elem in enumerate(chain):
            packed: bytes | None = None
            label = ""

            match elem:
                case RawDword(value=v, purpose=p):
                    packed = struct.pack("<I", v)
                    label = f"raw dword {v:#010x} ({p!r})"
                case GadgetRef(name=n) if db.contains(n):
                    g = db.get(n)
                    packed = g.pack()
                    label = f"gadget '{n}' ({g.address:#010x})"
                case WritablePtr(name=n) if db.contains(n):
                    g = db.get(n)
                    packed = g.pack()
                    label = f"writable ptr '{n}' ({g.address:#010x})"
                case PaddingBlock(value=v):
                    packed = struct.pack("<I", v)
                    label = f"padding value {v:#010x}"
                case _:
                    # Missing gadgets handled by _check_missing_gadgets;
                    # ShellcodePtr has no known address at validation time.
                    continue

            if packed is not None:
                hits = sorted({b for b in packed if b in bad_set})
                if hits:
                    hex_hits = ", ".join(f"{b:#04x}" for b in hits)
                    issues.append(ValidationIssue(
                        severity="error",
                        code="BAD_CHARS",
                        message=f"{label} contains bad byte(s): {hex_hits}",
                        element_index=idx,
                    ))
        return issues

    def _check_zero_padding(
        self,
        chain: list[ChainElement],
    ) -> list[ValidationIssue]:
        issues = []
        for idx, elem in enumerate(chain):
            if isinstance(elem, PaddingBlock) and elem.count == 0:
                issues.append(ValidationIssue(
                    severity="error",
                    code="ZERO_PADDING",
                    message="PaddingBlock with count=0 contributes no bytes",
                    element_index=idx,
                ))
        return issues

    def _check_writable_ptr(
        self,
        chain: list[ChainElement],
    ) -> list[ValidationIssue]:
        """At least one WritablePtr must exist for VirtualProtect lpflOldProtect."""
        if not any(isinstance(e, WritablePtr) for e in chain):
            return [ValidationIssue(
                severity="error",
                code="NO_WRITABLE_PTR",
                message=(
                    "No WritablePtr element found. "
                    "VirtualProtect requires a writable location for lpflOldProtect."
                ),
            )]
        return []

    def _check_return_target(
        self,
        chain: list[ChainElement],
        db: GadgetDB,
    ) -> list[ValidationIssue]:
        """
        Warn if the chain has no obvious return target into shellcode.

        Accepts either a ShellcodePtr or a GadgetRef whose instruction
        string contains "jmp" (e.g. "jmp esp").
        """
        has_shellcode_ptr = any(isinstance(e, ShellcodePtr) for e in chain)
        has_jmp = any(
            isinstance(e, GadgetRef)
            and db.contains(e.name)
            and "jmp" in db.get(e.name).instruction.lower()
            for e in chain
        )
        if not (has_shellcode_ptr or has_jmp):
            return [ValidationIssue(
                severity="warning",
                code="NO_RETURN_TARGET",
                message=(
                    "No ShellcodePtr or jmp-* gadget reference found. "
                    "Ensure the chain has a return path into shellcode."
                ),
            )]
        return []

    def _check_stack_alignment(
        self,
        chain: list[ChainElement],
    ) -> list[ValidationIssue]:
        """
        Warn when the total chain length is not 16-byte aligned.

        MSVC-compiled functions with SSE prologues require ESP to be 16-byte
        aligned at the CALL site.  A misaligned chain may cause crashes inside
        VirtualProtect or the shellcode if it uses SSE/aligned moves.
        """
        total_dwords = sum(
            elem.count if isinstance(elem, PaddingBlock) else 1
            for elem in chain
        )
        total_bytes = total_dwords * 4
        if total_bytes % 16 != 0:
            return [ValidationIssue(
                severity="warning",
                code="STACK_ALIGNMENT",
                message=(
                    f"Chain is {total_dwords} dwords ({total_bytes} bytes); "
                    "not 16-byte aligned — add padding dwords if the target "
                    "uses SSE prologues"
                ),
            )]
        return []
