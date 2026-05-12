"""
Thin Keystone wrapper. Kept separate so importing the rest of the package
does not require Keystone to be installed (useful for hash/encoding utilities
on non-Windows hosts).
"""

import sys


def assemble(code: str) -> tuple:
    """
    Assemble *code* using Keystone x86-32.

    Returns (shellcode_bytearray, instruction_count).
    Raises SystemExit on assembly error.
    """
    try:
        from keystone import Ks, KS_ARCH_X86, KS_MODE_32, KsError
    except ImportError:
        print('keystone-engine is not installed.  Run: pip install keystone-engine',
              file=sys.stderr)
        sys.exit(1)

    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    try:
        encoding, count = ks.asm(code)
    except KsError as e:
        print(f'Assembly error: {e}', file=sys.stderr)
        sys.exit(1)

    return bytearray(encoding), count
