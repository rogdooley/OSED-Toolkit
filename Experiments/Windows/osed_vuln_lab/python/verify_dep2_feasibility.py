#!/usr/bin/env python3
"""Validate instructor-only CDB evidence for the DEP-2 pivot gate."""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from pathlib import Path


OSED_STAGE_BYTES = 8192
_EVENT_PATTERN = re.compile(r"^DEP2 ([a-z_]+)=([0-9A-Fa-f]{1,8})$", re.MULTILINE)
_REQUIRED_EVENTS = {
    "saved_eip",
    "pivot_eip",
    "post_pivot_esp",
    "post_pivot_ret",
    "pre_pushad_esp",
}


class FeasibilityError(RuntimeError):
    """The CDB evidence does not establish the required staged-pivot path."""


@dataclass(frozen=True)
class FeasibilityEvidence:
    saved_eip: int
    pivot_eip: int
    post_pivot_esp: int
    post_pivot_ret: int
    pre_pushad_esp: int


def _parse_events(transcript: str) -> dict[str, int]:
    events: dict[str, int] = {}
    for name, value in _EVENT_PATTERN.findall(transcript):
        if name in events:
            raise FeasibilityError(f"duplicate DEP-2 event: {name}")
        events[name] = int(value, 16)

    missing = sorted(_REQUIRED_EVENTS - events.keys())
    if missing:
        raise FeasibilityError(f"missing DEP-2 event(s): {', '.join(missing)}")
    return events


def validate_transcript(
    transcript: str,
    *,
    saved_eip: int,
    pivot_eip: int,
    stage_base: int,
    stage2_offset: int,
    stage2_first_dword: int,
    proof_address: int,
) -> FeasibilityEvidence:
    """Validate the narrow control-flow evidence required before DEP-2 ROP work."""
    if not 0 <= stage2_offset < OSED_STAGE_BYTES:
        raise ValueError("stage2_offset must fall inside the staging buffer")

    events = _parse_events(transcript)
    if events["saved_eip"] != saved_eip:
        raise FeasibilityError("saved EIP does not contain the expected first-stage gadget")
    if events["pivot_eip"] != pivot_eip:
        raise FeasibilityError("pivot gadget was not reached")

    stage2_start = stage_base + stage2_offset
    stage_end = stage_base + OSED_STAGE_BYTES
    if not stage2_start <= events["post_pivot_esp"] < stage_end:
        raise FeasibilityError("post-pivot ESP is outside the staged chain")
    if events["post_pivot_ret"] != stage2_first_dword:
        raise FeasibilityError("first staged RET target is incorrect")
    if events["pre_pushad_esp"] != proof_address:
        raise FeasibilityError("pre-PUSHAD ESP does not equal the proof address")

    return FeasibilityEvidence(**events)


def _address(value: str) -> int:
    result = int(value, 0)
    if not 0 <= result <= 0xFFFFFFFF:
        raise argparse.ArgumentTypeError("address must fit in a 32-bit DWORD")
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--transcript", type=Path, required=True)
    parser.add_argument("--saved-eip", type=_address, required=True)
    parser.add_argument("--pivot-eip", type=_address, required=True)
    parser.add_argument("--stage-base", type=_address, required=True)
    parser.add_argument("--stage2-offset", type=_address, required=True)
    parser.add_argument("--stage2-first-dword", type=_address, required=True)
    parser.add_argument("--proof-address", type=_address, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        evidence = validate_transcript(
            args.transcript.read_text(encoding="utf-8"),
            saved_eip=args.saved_eip,
            pivot_eip=args.pivot_eip,
            stage_base=args.stage_base,
            stage2_offset=args.stage2_offset,
            stage2_first_dword=args.stage2_first_dword,
            proof_address=args.proof_address,
        )
    except (FeasibilityError, OSError, ValueError) as error:
        print(f"DEP-2 feasibility failed: {error}")
        return 1

    print(
        "DEP-2 feasibility passed: "
        f"pivot=0x{evidence.pivot_eip:08X} "
        f"post_pivot_esp=0x{evidence.post_pivot_esp:08X} "
        f"pre_pushad_esp=0x{evidence.pre_pushad_esp:08X}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
