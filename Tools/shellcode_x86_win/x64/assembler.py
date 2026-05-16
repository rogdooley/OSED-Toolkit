"""
x64 assembler — thin re-export of shellcode.assembler.assemble64.
Imported here so shellcode.x64 has a self-contained namespace.
"""

from shellcode.assembler import assemble64

__all__ = ['assemble64']
