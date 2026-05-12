"""
Network encoding helpers and null-byte-safe stack string builder.
"""

import struct


def encode_ip(ip: str) -> tuple:
    """
    Return (push_value, has_null) for a dotted-quad IPv4 address.

    push_value is the little-endian dword to use in 'push <value>' so that
    the four bytes land in network byte order (big-endian) at ESP.
    has_null is True when any octet is zero.
    """
    octets = [int(x) for x in ip.split('.')]
    val = octets[0] | (octets[1] << 8) | (octets[2] << 16) | (octets[3] << 24)
    return val, any(o == 0 for o in octets)


def encode_port(port: int) -> tuple:
    """
    Return (mov_ax_value, has_null) for a port number.

    mov_ax_value is the byte-swapped port for 'mov ax, <value>' so the bytes
    land in network byte order at that stack slot.
    has_null is True when either byte of the swapped value is zero.
    """
    swapped = ((port & 0xFF) << 8) | (port >> 8)
    return swapped, (swapped & 0xFF == 0 or (swapped >> 8) == 0)


def stack_string_pushes(s: str) -> list:
    """
    Return a list of x86 assembly instruction strings that build the
    null-terminated ASCII string *s* on the stack, null-byte-safe.

    After executing the returned instructions, ESP points to the string.
    Five cases are handled:
      - No nulls in the chunk: plain push <dword>
      - Only trailing null bytes (align padding): mov ax / mov al variants
      - Single trailing null (high byte): 3× mov-al-shl sequence
      - Embedded nulls in a non-terminal chunk: warning comment emitted
    """
    data = s.encode('ascii') + b'\x00'
    while len(data) % 4:
        data += b'\x00'

    chunks = [data[i:i+4] for i in range(0, len(data), 4)]
    lines = []

    for chunk in reversed(chunks):
        val     = struct.unpack('<I', chunk)[0]
        label   = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        comment = f'# "{label}"'
        nulls   = [i for i, b in enumerate(chunk) if b == 0]

        if val == 0:
            lines += ['xor eax, eax', f'push eax                    {comment}']
        elif nulls == [2, 3]:
            word = struct.unpack('<H', chunk[:2])[0]
            lines += ['xor eax, eax', f'mov ax, {hex(word):<10}         {comment}', 'push eax']
        elif nulls == [1, 2, 3]:
            lines += ['xor eax, eax', f'mov al, {hex(chunk[0]):<10}         {comment}', 'push eax']
        elif nulls == [3]:
            lines += [
                'xor eax, eax',
                f'mov al, {hex(chunk[2])}',
                'shl eax, 0x08',
                f'mov al, {hex(chunk[1])}',
                'shl eax, 0x08',
                f'mov al, {hex(chunk[0])}             {comment}',
                'push eax',
            ]
        elif nulls:
            lines += [
                f'# WARNING: embedded null in {chunk.hex()} ("{label}") - manual fix required',
                f'push {hex(val):<18}     {comment}',
            ]
        else:
            lines += [f'push {hex(val):<18}     {comment}']

    return lines
