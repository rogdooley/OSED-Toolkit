"""
Thin Keystone wrapper. Kept separate so importing the rest of the package
does not require Keystone to be installed (useful for hash/encoding utilities
on non-Windows hosts).

Supports both x86-32 and x86-64 via the internal _assemble() helper.
Public surface:
    assemble(code)    -> (bytearray, int)   x86-32
    assemble64(code)  -> (bytearray, int)   x86-64
"""

import sys


def _assemble(code: str, mode_32: bool) -> tuple:
    """
    Assemble *code* with Keystone.

    mode_32=True  → KS_MODE_32 (x86)
    mode_32=False → KS_MODE_64 (x64)

    Returns (shellcode_bytearray, instruction_count).
    Raises SystemExit on missing Keystone or assembly error.
    """
    try:
        from keystone import Ks, KS_ARCH_X86, KS_MODE_32, KS_MODE_64, KsError
    except ImportError:
        print('keystone-engine is not installed.  Run: pip install keystone-engine',
              file=sys.stderr)
        sys.exit(1)

    mode = KS_MODE_32 if mode_32 else KS_MODE_64
    ks   = Ks(KS_ARCH_X86, mode)

    try:
        encoding, count = ks.asm(code)
    except KsError as e:
        label = '32-bit' if mode_32 else '64-bit'
        print(f'Assembly error ({label}): {e}', file=sys.stderr)
        sys.exit(1)

    return bytearray(encoding), count


def assemble(code: str) -> tuple:
    """
    Assemble *code* using Keystone x86-32.
    Returns (shellcode_bytearray, instruction_count).
    """
    return _assemble(code, mode_32=True)


def assemble64(code: str) -> tuple:
    """
    Assemble *code* using Keystone x86-64.
    Returns (shellcode_bytearray, instruction_count).
    """
    return _assemble(code, mode_32=False)


def check_bad_chars(shellcode, bad_chars):
    """
    Return list of (offset, byte_value) for every byte in *shellcode*
    that appears in *bad_chars*.  Empty list = clean.

    Example::

        hits = check_bad_chars(sc, b'\\x00\\x0a\\x0d')
        if hits:
            for offset, val in hits:
                print(f'  0x{offset:04x}: 0x{val:02x}')
    """
    bad_set = set(bad_chars)
    return [(i, b) for i, b in enumerate(shellcode) if b in bad_set]
