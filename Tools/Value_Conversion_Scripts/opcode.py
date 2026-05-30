#!/usr/bin/env python3

import sys

def ror_str(byte, count):
    # Perform right rotation of `byte` by `count` bits within 32-bit range
    return ((byte >> count) | (byte << (32 - count))) & 0xFFFFFFFF

if __name__ == '__main__':
    try:
        esi = sys.argv[1]
    except IndexError:
        print("Usage: %s INPUTSTRING" % sys.argv[0])
        sys.exit()

    # Initialize variables
    edx = 0x00
    ror_count = 0

    for eax in esi:
        edx += ord(eax)
        if ror_count < len(esi)-1:
            edx = ror_str(edx, 0xd)  # Rotate `edx` by 13 bits
        ror_count += 1

    print(hex(edx))