"""EBP-relative slot manager for saved function pointers."""


class SlotAllocator:
    """
    Tracks EBP-relative dword slots for saved function pointers.

    Layout:
        [ebp+0x04]  reserved by the call/pop thunk for find_function
        [ebp+0x10]  first user slot (increments by 4 per allocation)

    Usage::

        slots = SlotAllocator()
        slots.alloc('LoadLibraryA')    # returns 0x10, reserves [ebp+0x10]
        slots.alloc('CreateProcessA')  # returns 0x14
        slots.slot('LoadLibraryA')     # returns 0x10 (lookup without alloc)
        slots.hex_slot('LoadLibraryA') # returns '0x10'
    """

    FIND_FUNCTION = 0x04

    def __init__(self, start: int = 0x10):
        self._map:  dict = {}
        self._next: int  = start

    def alloc(self, name: str) -> int:
        """Allocate a slot for *name* (idempotent — returns existing if already allocated)."""
        if name not in self._map:
            self._map[name] = self._next
            self._next += 4
        return self._map[name]

    def slot(self, name: str) -> int:
        """Return the slot offset for *name*. Raises KeyError if not yet allocated."""
        return self._map[name]

    def hex_slot(self, name: str) -> str:
        """Return the slot offset for *name* as a hex string."""
        return hex(self._map[name])

    def as_dict(self) -> dict:
        """Return a copy of the name→offset mapping."""
        return dict(self._map)

    def print_map(self):
        """Print the current slot assignments to stdout."""
        print('  Slot map:')
        print('    [ebp+0x04] = find_function  (reserved)')
        for name, offset in self._map.items():
            print(f'    [ebp+{hex(offset)}] = {name}')
