"""
shellcode.x64 — x64 Windows shellcode building blocks.

Public API mirrors shellcode (x86) but all assembly targets 64-bit Windows.

    from shellcode.x64 import bindshell_code, assemble64

Key differences from shellcode (x86):
  - GS:[0x60] for PEB (not FS:[0x30])
  - Microsoft x64 fastcall: first 4 args in RCX/RDX/R8/R9, 32-byte shadow space
  - No pushad/popad — registers saved/restored manually
  - 8-byte function pointer slots at negative RBP offsets
  - STARTUPINFOA.cb = 0x68 (not 0x44)
  - 16-byte stack alignment required before every CALL

Hashing and network encoding are shared with the x86 package — they are
pure Python and architecture-independent.
"""

# Shared with x86 — no duplication
from shellcode.hashing import (
    ror_hash,
    rolxor_hash,
    compute_hash,
    ALGOS,
    DEFAULT_ROTATION,
)
from shellcode.encoding import (
    encode_ip,
    encode_port,
    stack_string_pushes,
)

# x64-specific
from .slots import SlotAllocator64

from .snippets import (
    SNIPPET_STARTUPINFOA_SOCKET,
    SNIPPET_STARTUPINFOA_NULL,
    SNIPPET_CMD_STRING,
    snippet_createprocessa,
    snippet_terminateprocess,
    snippet_wsa_init,
    snippet_wsa_socket_tcp,
    snippet_sockaddr_bind,
    snippet_bind_listen_accept,
    snippet_wsaconnect,
)
from .builders import (
    custom_code,
    bindshell_code,
    revshell_code,
    loader_code,
    build_resolve_block,
    build_load_and_resolve,
    build_call_placeholder,
)
from .assembler import assemble64

__all__ = [
    # shared hashing
    'ror_hash', 'rolxor_hash', 'compute_hash', 'ALGOS', 'DEFAULT_ROTATION',
    # shared encoding
    'encode_ip', 'encode_port', 'stack_string_pushes',
    # x64 slots
    'SlotAllocator64',
    # x64 snippets
    'SNIPPET_STARTUPINFOA_SOCKET', 'SNIPPET_STARTUPINFOA_NULL', 'SNIPPET_CMD_STRING',
    'snippet_createprocessa', 'snippet_terminateprocess',
    'snippet_wsa_init', 'snippet_wsa_socket_tcp',
    'snippet_sockaddr_bind', 'snippet_bind_listen_accept', 'snippet_wsaconnect',
    # x64 mode builders
    'custom_code', 'bindshell_code', 'revshell_code', 'loader_code',
    # x64 builder primitives
    'build_resolve_block', 'build_load_and_resolve', 'build_call_placeholder',
    # x64 assembler
    'assemble64',
]
