"""
payload_builder.py

Layout-driven payload builder that assembles raw bytes deterministically
from a :class:`LayoutSpec`.

Design decisions:
  - Uses bytearray throughout to avoid O(n²) concatenation.
  - Single-pass construction where possible; overlap/offset checks are O(n).
  - Computed segments are resolved at build time via computed_registry.
  - at_offset segments are written after the initial pass so they can
    overwrite padding at exact positions — this is intentional and explicit.
  - Badchar validation is one final scan O(n) over the finished payload.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from Tools.exploit.computed_registry import BuildContext, call as registry_call
from Tools.exploit.layout_spec import (
    AtOffsetSegment,
    BytesFileSegment,
    ComputedSegment,
    LayoutSpec,
    PadSegment,
    RawBytesSegment,
    RepeatSegment,
    Segment,
)


# ---------------------------------------------------------------------------
# Validation errors
# ---------------------------------------------------------------------------

class PayloadBuildError(Exception):
    """Raised when the builder cannot produce a valid payload."""


class BadcharError(PayloadBuildError):
    """Raised when the final payload contains a forbidden byte."""

    def __init__(self, violations: list[tuple[int, int, str]]) -> None:
        """
        Args:
            violations: List of (offset, byte_value, segment_name).
        """
        self.violations = violations
        lines = [
            f"  Badchar 0x{bv:02X} at offset {off} (segment: {seg})"
            for off, bv, seg in violations
        ]
        super().__init__("Badchar violations found:\n" + "\n".join(lines))


class OverlapError(PayloadBuildError):
    """Raised when two segments would occupy overlapping byte ranges."""


# ---------------------------------------------------------------------------
# Segment placement record (for overlap detection and context)
# ---------------------------------------------------------------------------

@dataclass
class PlacedSegment:
    name: str
    start: int
    end: int          # exclusive


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------

class PayloadBuilder:
    """
    Assembles a raw byte payload from a :class:`LayoutSpec`.

    Args:
        badchars: Additional bytes to forbid, merged with spec-level badchars.
        strict_overlap: If True, raise on any overlap (even at_offset overwrites).
                        If False (default), at_offset segments may overwrite padding.
    """

    def __init__(
        self,
        badchars: bytes | None = None,
        strict_overlap: bool = False,
    ) -> None:
        self._extra_badchars: bytes = badchars or b""
        self._strict_overlap = strict_overlap

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build(self, spec: LayoutSpec) -> bytes:
        """Build and return raw payload bytes.

        Raises:
            PayloadBuildError: On layout violations.
            BadcharError: If the final payload contains forbidden bytes.
        """
        merged_badchars = bytes(set(spec.badchars) | set(self._extra_badchars))
        buf, placed = self._assemble(spec)
        self._validate_badchars(buf, placed, merged_badchars)
        if spec.expected_total_size is not None and len(buf) != spec.expected_total_size:
            raise PayloadBuildError(
                f"Expected payload size {spec.expected_total_size}, "
                f"got {len(buf)}"
            )
        return bytes(buf)

    def build_and_optionally_write(
        self,
        spec: LayoutSpec,
        output_file: str | None = None,
    ) -> bytes:
        """Build payload and optionally write it to *output_file*.

        Args:
            spec: Parsed layout spec.
            output_file: If provided, write raw bytes to this path.

        Returns:
            The assembled payload bytes.
        """
        payload = self.build(spec)
        if output_file is not None:
            out = Path(output_file)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(payload)
        return payload

    # ------------------------------------------------------------------
    # Internal assembly
    # ------------------------------------------------------------------

    def _assemble(self, spec: LayoutSpec) -> tuple[bytearray, list[PlacedSegment]]:
        """
        Two-pass assembly:
          Pass 1: Sequential segments (pad, repeat, bytes_file, raw_bytes, computed).
          Pass 2: at_offset segments written at exact positions (may overwrite padding).
        """
        buf = bytearray()
        placed: list[PlacedSegment] = []
        segment_offsets: dict[str, int] = {}

        at_offset_queue: list[tuple[AtOffsetSegment, int]] = []

        # Pass 1 — sequential segments
        for seg in spec.segments:
            if isinstance(seg, AtOffsetSegment):
                at_offset_queue.append((seg, len(buf)))
                continue

            start = len(buf)
            chunk = self._resolve_segment(seg, buf, segment_offsets, spec)
            buf.extend(chunk)
            end = len(buf)

            p = PlacedSegment(name=seg.name, start=start, end=end)
            self._check_overlap(p, placed)
            placed.append(p)
            segment_offsets[seg.name] = start

        # Pass 2 — at_offset segments (write at exact positions, extending buf if needed)
        for seg, _ in at_offset_queue:
            chunk = self._resolve_at_offset(seg)
            target = seg.at_offset
            needed = target + len(chunk)
            if needed > len(buf):
                buf.extend(b"\x00" * (needed - len(buf)))

            p = PlacedSegment(name=seg.name, start=target, end=target + len(chunk))
            if self._strict_overlap:
                self._check_overlap(p, placed)

            buf[target : target + len(chunk)] = chunk
            placed.append(p)
            segment_offsets[seg.name] = target

        return buf, placed

    def _resolve_segment(
        self,
        seg: Segment,
        buf: bytearray,
        segment_offsets: dict[str, int],
        spec: LayoutSpec,
    ) -> bytes:
        current_offset = len(buf)

        if isinstance(seg, PadSegment):
            target = seg.until_offset
            if target < current_offset:
                raise PayloadBuildError(
                    f"Segment '{seg.name}': until_offset={target} is before "
                    f"current offset {current_offset}"
                )
            return bytes([seg.pad_byte] * (target - current_offset))

        if isinstance(seg, RepeatSegment):
            return bytes([seg.byte] * seg.count)

        if isinstance(seg, BytesFileSegment):
            p = Path(seg.path)
            if not p.exists():
                raise PayloadBuildError(
                    f"Segment '{seg.name}': bytes_file not found: {p}"
                )
            return p.read_bytes()

        if isinstance(seg, RawBytesSegment):
            return seg.data

        if isinstance(seg, ComputedSegment):
            ctx = BuildContext(
                current_offset=current_offset,
                total_size=spec.expected_total_size or 0,
                segment_offsets=dict(segment_offsets),
            )
            return registry_call(seg.computed.function, seg.computed.args, ctx)

        raise TypeError(f"Unknown segment type: {type(seg).__name__}")

    def _resolve_at_offset(self, seg: AtOffsetSegment) -> bytes:
        if seg.dword is not None:
            endian: str = seg.endian or "little"
            return seg.dword.to_bytes(4, endian)  # type: ignore[arg-type]
        if seg.raw_bytes is not None:
            return seg.raw_bytes
        raise PayloadBuildError(f"Segment '{seg.name}': no data for at_offset segment")

    # ------------------------------------------------------------------
    # Validation helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _check_overlap(new: PlacedSegment, placed: list[PlacedSegment]) -> None:
        for existing in placed:
            if new.start < existing.end and new.end > existing.start:
                raise OverlapError(
                    f"Segment '{new.name}' [{new.start}:{new.end}] overlaps "
                    f"'{existing.name}' [{existing.start}:{existing.end}]"
                )

    @staticmethod
    def _validate_badchars(
        buf: bytearray,
        placed: list[PlacedSegment],
        badchars: bytes,
    ) -> None:
        if not badchars:
            return

        bad_set = set(badchars)
        # Build offset→segment name map (last writer wins for at_offset overwrites)
        offset_to_seg: dict[int, str] = {}
        for p in placed:
            for i in range(p.start, p.end):
                offset_to_seg[i] = p.name

        violations: list[tuple[int, int, str]] = []
        for i, bv in enumerate(buf):
            if bv in bad_set:
                seg_name = offset_to_seg.get(i, "<unknown>")
                violations.append((i, bv, seg_name))

        if violations:
            raise BadcharError(violations)
