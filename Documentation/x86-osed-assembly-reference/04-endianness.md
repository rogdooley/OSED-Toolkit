# 4. Endianness

## Byte Order in Memory

x86 is little-endian: the least significant byte is stored at the lowest
address.

```
Value: 0x625011AF

Memory (low address first):
+0x00: AF
+0x01: 11
+0x02: 50
+0x03: 62

WinDbg `db` output:  AF 11 50 62
WinDbg `dd` output:  625011AF
```

`db` shows raw bytes in memory order. `dd` reconstructs the DWORD by reading
4 bytes little-endian and displaying the integer value.

## Impact on Exploit Development

### Overwritten EIP

When you overwrite a saved return address with `0x625011AF`, you write the bytes
`AF 11 50 62` into memory. The CPU reads these 4 bytes little-endian and loads
`0x625011AF` into EIP on `ret`.

### ROP Chains

Every address in a ROP chain must be written in little-endian order. In Python:

```python
import struct

addr = 0x625011AF
payload = struct.pack("<I", addr)   # b'\xaf\x11Pb'
```

### Python Packing

```python
from struct import pack, unpack

# Pack a 32-bit integer as little-endian bytes
packed = pack("<I", 0x625011AF)        # b'\xaf\x11Pb'

# Unpack 4 bytes back to an integer
value = unpack("<I", b'\xaf\x11Pb')[0] # 0x625011AF

# Common helper
def p32(v: int) -> bytes:
    return pack("<I", v & 0xFFFFFFFF)
```

### Debugger Memory Display

```
0:000> dd esp L4
0012ff80  625011af 41414141 42424242 43434343

0:000> db esp L10
0012ff80  af 11 50 62 41 41 41 41-42 42 42 42 43 43 43 43
```

The `dd` view shows reconstructed DWORDs; the `db` view shows raw byte order.
When constructing payloads, think in `db` order (the bytes you actually send)
and verify with `dd` (the values the CPU will interpret).

### Unicode and UTF-16

Windows uses UTF-16LE for Unicode strings. Each character is 2 bytes,
little-endian. The ASCII character `A` (0x41) becomes `41 00` in UTF-16LE.
This matters when comparing module names in PEB walking -- the names are
stored as UNICODE_STRING (UTF-16LE).
