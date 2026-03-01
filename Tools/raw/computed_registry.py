"""
computed_registry.py

Pluggable registry for computed byte-generation functions used by PayloadBuilder.

Design constraints:
- No eval(), no dynamic imports from layout specs.
- Only explicitly registered functions are callable.
- Functions may optionally accept a BuildContext for offset-aware calculations.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

# ---------------------------------------------------------------------------
# Build context (optional second argument to computed functions)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class BuildContext:
    """
    Immutable snapshot of builder state at the point a computed segment is resolved.

    Attributes:
        current_offset: Byte offset at which this segment will be placed.
        total_size: Expected total payload size (may be 0 if unknown).
        segment_offsets: Mapping of segment name → start offset for already-placed segments.
    """
    current_offset: int
    total_size: int
    segment_offsets: dict[str, int] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Type alias
# ---------------------------------------------------------------------------

# A computed function either accepts (args) or (args, context).
ComputedFunc = Callable[..., bytes]

COMPUTED_REGISTRY: dict[str, ComputedFunc] = {}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def register(name: str, func: ComputedFunc) -> None:
    """Register a named computation function.

    Args:
        name: Identifier used in layout specs under ``computed.function``.
        func: Callable accepting ``(args: dict)`` or ``(args: dict, ctx: BuildContext)``
              and returning raw bytes.

    Raises:
        ValueError: If *name* is already registered (use ``force=True`` to override).
    """
    COMPUTED_REGISTRY[name] = func


def register_force(name: str, func: ComputedFunc) -> None:
    """Like :func:`register` but silently overwrites existing entries."""
    COMPUTED_REGISTRY[name] = func


def call(name: str, args: dict, ctx: BuildContext) -> bytes:
    """Look up and invoke a registered computation function.

    The function is called with ``(args, ctx)`` first; if it raises ``TypeError``
    (wrong arity), it is retried with just ``(args,)``.

    Args:
        name: Registered function name.
        args: Argument dict from the layout spec.
        ctx:  Current :class:`BuildContext`.

    Returns:
        Raw bytes produced by the function.

    Raises:
        KeyError: If *name* is not registered.
        TypeError: If the function signature is incompatible.
    """
    if name not in COMPUTED_REGISTRY:
        raise KeyError(
            f"No computed function '{name}' registered. "
            f"Available: {sorted(COMPUTED_REGISTRY)}"
        )
    func = COMPUTED_REGISTRY[name]
    try:
        result = func(args, ctx)
    except TypeError:
        # Fallback: function only accepts (args,)
        result = func(args)
    if not isinstance(result, (bytes, bytearray)):
        raise TypeError(
            f"Computed function '{name}' must return bytes, got {type(result).__name__}"
        )
    return bytes(result)


# ---------------------------------------------------------------------------
# Built-in utility functions (always available)
# ---------------------------------------------------------------------------

def _short_jump_back(args: dict) -> bytes:
    """
    Generate a short relative JMP (EB xx) that jumps backwards.

    args:
        distance (int): Number of bytes to jump backwards from *after* the instruction.
                        The encoded offset will be (256 - distance) to get a negative rel8.
    """
    distance: int = int(args["distance"])
    if not (1 <= distance <= 256):
        raise ValueError(f"short_jump_back: distance must be 1-256, got {distance}")
    encoded = (256 - distance) & 0xFF
    return bytes([0xEB, encoded])


def _nop_sled(args: dict) -> bytes:
    """Generate a NOP sled of *count* bytes."""
    count: int = int(args.get("count", 16))
    return b"\x90" * count


def _xor_encoder(args: dict) -> bytes:
    """XOR-encode *size* bytes of 0x00 with *key*. Placeholder for real shellcode."""
    key: int = int(args["key"]) & 0xFF
    size: int = int(args["size"])
    return bytes([key ^ 0x00] * size)


def _rel32_jump(args: dict, ctx: BuildContext) -> bytes:
    """
    Generate a 32-bit relative JMP (E9 xx xx xx xx) to a named segment.

    args:
        to_segment (str): Name of target segment (must already be placed).
    """
    target_name: str = args["to_segment"]
    if target_name not in ctx.segment_offsets:
        raise KeyError(
            f"rel32_jump: target segment '{target_name}' not yet placed. "
            "Place it before this computed segment."
        )
    target_offset = ctx.segment_offsets[target_name]
    # Instruction is 5 bytes; rel32 is relative to end of instruction.
    after_instr = ctx.current_offset + 5
    rel32 = (target_offset - after_instr) & 0xFFFFFFFF
    return b"\xE9" + rel32.to_bytes(4, "little")


# Register built-ins
register("short_jump_back", _short_jump_back)
register("nop_sled", _nop_sled)
register("xor_encoder", _xor_encoder)
register("rel32_jump", _rel32_jump)
