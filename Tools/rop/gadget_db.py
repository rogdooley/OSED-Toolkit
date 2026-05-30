"""
GadgetDB — loads and queries a user-supplied gadget database.

JSON schema
-----------
::

    {
      "<name>": {
        "address":     "0x10012345",   // hex string (preferred) or integer
        "module":      "libspp.dll",   // owning module name
        "instruction": "pop eax; ret"  // human-readable disassembly
      },
      ...
    }

Addresses must be non-zero 32-bit values; the tool never generates or guesses
gadget addresses — every address must come from this file.
"""

from __future__ import annotations

import json
from pathlib import Path

from Tools.rop.models import Gadget


class GadgetDBError(ValueError):
    """Raised when the database cannot be loaded or a lookup fails."""


class GadgetDB:
    """
    Immutable, case-sensitive gadget database.

    Load from a JSON file with :meth:`from_file` or from a plain dict with
    :meth:`from_dict` (useful in tests).
    """

    def __init__(self, data: dict[str, dict]) -> None:
        self._gadgets: dict[str, Gadget] = {}
        for name, entry in data.items():
            try:
                raw = entry["address"]
                address = int(raw, 16) if isinstance(raw, str) else int(raw)
                if not (0 < address <= 0xFFFFFFFF):
                    raise ValueError(f"address {address:#x} is not a valid 32-bit non-zero value")
                self._gadgets[name] = Gadget(
                    address=address,
                    module=str(entry.get("module", "unknown")),
                    instruction=str(entry.get("instruction", "")),
                )
            except (KeyError, ValueError, TypeError) as exc:
                raise GadgetDBError(
                    f"Invalid gadget entry '{name}': {exc}"
                ) from exc

    # ── Constructors ─────────────────────────────────────────────────────────

    @classmethod
    def from_file(cls, path: Path | str) -> GadgetDB:
        """Load from a JSON file on disk."""
        p = Path(path)
        try:
            raw = p.read_text(encoding="utf-8")
        except OSError as exc:
            raise GadgetDBError(f"Cannot read gadget file '{p}': {exc}") from exc
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise GadgetDBError(f"Invalid JSON in '{p}': {exc}") from exc
        if not isinstance(data, dict):
            raise GadgetDBError(
                f"Gadget file must be a JSON object, got {type(data).__name__}"
            )
        return cls(data)

    @classmethod
    def from_dict(cls, data: dict[str, dict]) -> GadgetDB:
        """Construct directly from a Python dict (useful for tests)."""
        return cls(data)

    # ── Query interface ───────────────────────────────────────────────────────

    def get(self, name: str) -> Gadget:
        """
        Return the Gadget for *name*.

        :raises GadgetDBError: if *name* is not in the database.
        """
        try:
            return self._gadgets[name]
        except KeyError:
            known = ", ".join(sorted(self._gadgets)) or "(none)"
            raise GadgetDBError(
                f"Gadget '{name}' not found in database. "
                f"Known gadgets: {known}"
            ) from None

    def contains(self, name: str) -> bool:
        return name in self._gadgets

    def names(self) -> list[str]:
        return sorted(self._gadgets)

    def __len__(self) -> int:
        return len(self._gadgets)

    def __repr__(self) -> str:
        return f"GadgetDB({len(self)} gadgets)"
