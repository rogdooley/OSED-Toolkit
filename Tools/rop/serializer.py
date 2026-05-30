"""
ChainSerializer — converts a symbolic ROP chain to raw bytes.

Every ChainElement is resolved to a 4-byte little-endian value:

    RawDword      → struct.pack("<I", value)
    GadgetRef     → gadget address from GadgetDB
    WritablePtr   → writable address from GadgetDB
    ShellcodePtr  → shellcode_addr supplied by the caller
    PaddingBlock  → value repeated count times

ShellcodePtr requires a concrete runtime address.  Pass it via
``shellcode_addr``; the serializer raises SerializationError if one is
present in the chain but the argument is omitted.

Run ChainValidator first — the serializer does not duplicate validation
logic and will raise GadgetDBError for missing gadgets.
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
    WritablePtr,
)


class SerializationError(ValueError):
    """Raised when the chain cannot be converted to bytes."""


class ChainSerializer:
    """
    Serialize a symbolic ROP chain to a raw bytes object.

    Example::

        ser = ChainSerializer()
        raw = ser.serialize(chain, db, shellcode_addr=0x00419000)
    """

    def serialize(
        self,
        chain: Sequence[ChainElement],
        db: GadgetDB,
        shellcode_addr: int | None = None,
    ) -> bytes:
        """
        Convert every element to bytes and concatenate.

        Parameters
        ----------
        chain:
            Symbolic chain from a planner or RopChain.elements().
        db:
            GadgetDB used to resolve GadgetRef and WritablePtr names.
        shellcode_addr:
            Runtime address of the shellcode base.  Required when the chain
            contains any ShellcodePtr element.

        :raises SerializationError: on a missing shellcode_addr or unknown type.
        :raises GadgetDBError: if a referenced gadget is absent from *db*.
        """
        parts: list[bytes] = []
        for idx, elem in enumerate(chain):
            try:
                parts.append(self._pack(elem, db, shellcode_addr))
            except SerializationError:
                raise
            except Exception as exc:
                raise SerializationError(
                    f"Cannot serialize element [{idx}] ({type(elem).__name__}): {exc}"
                ) from exc
        return b"".join(parts)

    def _pack(
        self,
        elem: ChainElement,
        db: GadgetDB,
        shellcode_addr: int | None,
    ) -> bytes:
        match elem:
            case RawDword(value=v):
                return struct.pack("<I", v)

            case GadgetRef(name=n):
                return db.get(n).pack()

            case WritablePtr(name=n):
                return db.get(n).pack()

            case ShellcodePtr():
                if shellcode_addr is None:
                    raise SerializationError(
                        "Chain contains ShellcodePtr but shellcode_addr was not supplied "
                        "to serialize(). Pass the runtime shellcode address or replace "
                        "ShellcodePtr with a RawDword if the address is known ahead of time."
                    )
                if not (0 <= shellcode_addr <= 0xFFFFFFFF):
                    raise SerializationError(
                        f"shellcode_addr {shellcode_addr!r} is outside the 32-bit range"
                    )
                return struct.pack("<I", shellcode_addr)

            case PaddingBlock(count=c, value=v):
                return struct.pack("<I", v) * c

            case _:
                raise SerializationError(
                    f"Unknown ChainElement type: {type(elem).__name__}"
                )
