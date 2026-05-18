"""
x64 EBP/RBP-relative slot manager for saved function pointers.

x64 differences from x86:
  - Pointers are 8 bytes, so slots step by 8 (not 4)
  - Slots are stored at negative RBP offsets: [rbp-0x08], [rbp-0x10], ...
    This keeps them below the stack frame base, out of the way of the
    shadow space that fastcall requires above RSP before each CALL.
  - [rbp-0x08] is permanently reserved for the find_function pointer
    (same role as [ebp+0x04] in x86, just relocated)
"""


class SlotAllocator64:
    """
    Tracks RBP-relative 8-byte slots for saved function pointers.

    Layout (negative offsets from RBP):
        [rbp-0x08]   find_function pointer  — permanently reserved
        [rbp-0x10]   first user slot
        [rbp-0x18]   second user slot
        ...

    Usage::

        slots = SlotAllocator64()
        slots.alloc('LoadLibraryA')    # returns -0x10
        slots.alloc('CreateProcessA')  # returns -0x18
        slots.slot('LoadLibraryA')     # returns -0x10
        slots.asm_slot('LoadLibraryA') # returns 'rbp-0x10'
    """

    FIND_FUNCTION = -0x08   # [rbp-0x08]

    def __init__(self, start: int = -0x10):
        self._map:  dict = {}
        self._next: int  = start      # decrements by 8 each allocation

    def alloc(self, name: str) -> int:
        """Allocate a slot for *name* (idempotent)."""
        if name not in self._map:
            self._map[name] = self._next
            self._next -= 8
        return self._map[name]

    def slot(self, name: str) -> int:
        """Return the slot offset for *name*. Raises KeyError if not allocated."""
        return self._map[name]

    def asm_slot(self, name: str) -> str:
        """Return the slot as an assembly operand string, e.g. 'rbp-0x10'."""
        offset = self._map[name]
        if offset < 0:
            return f'rbp-{hex(-offset)}'
        return f'rbp+{hex(offset)}'

    def asm_find_function(self) -> str:
        """Assembly operand for the find_function slot."""
        return 'rbp-0x08'

    def hex_offset(self, name: str) -> str:
        """Return the raw offset as a signed hex string, e.g. '-0x10'."""
        offset = self._map[name]
        return f'-{hex(-offset)}' if offset < 0 else hex(offset)

    def as_dict(self) -> dict:
        """Copy of the name → offset mapping."""
        return dict(self._map)

    def print_map(self):
        """Print slot assignments to stdout."""
        print('  Slot map (x64):')
        print('    [rbp-0x08] = find_function  (reserved)')
        for name, offset in self._map.items():
            sign = '-' if offset < 0 else '+'
            magnitude = hex(abs(offset))
            print(f'    [rbp{sign}{magnitude}] = {name}')
