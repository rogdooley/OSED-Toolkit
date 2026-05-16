"""
shellcode — x86 Windows shellcode building blocks.

Public API
----------
Hashing:
    ror_hash(name, rotation=13)         ROR-N + ADD per byte
    rolxor_hash(name, rotation=7)       ROL-N + XOR per byte
    compute_hash(name, algo, rotation)  dispatch by algo string

Network encoding:
    encode_ip(ip)       (push_value, has_null)
    encode_port(port)   (mov_ax_value, has_null)

Stack strings:
    stack_string_pushes(s)   list of null-byte-safe push instructions

Slot management:
    SlotAllocator            tracks EBP-relative function pointer slots

Assembly snippets (strings / functions):
    SNIPPET_STARTUPINFOA_SOCKET
    SNIPPET_STARTUPINFOA_NULL
    SNIPPET_CMD_STRING
    snippet_createprocessa(slot)
    snippet_terminateprocess(slot)
    snippet_wsa_init(slot)
    snippet_wsa_socket_tcp(slot)
    snippet_sockaddr_bind(port)
    snippet_bind_listen_accept(bind_slot, listen_slot, accept_slot)
    snippet_wsaconnect(lhost, lport, slot)

Mode builders (return (asm_string, SlotAllocator)):
    custom_code(func_names, algo, rotation)
    bindshell_code(port, algo, rotation)
    revshell_code(lhost, lport, algo, rotation)

Assembler:
    assemble(code)   (bytearray, instruction_count)
"""

from .hashing import (
    ror_hash,
    rolxor_hash,
    compute_hash,
    ALGOS,
    DEFAULT_ROTATION,
)
from .encoding import (
    encode_ip,
    encode_port,
    stack_string_pushes,
)
from .slots import SlotAllocator
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
)
from .assembler import assemble, assemble64

__all__ = [
    # hashing
    'ror_hash', 'rolxor_hash', 'compute_hash', 'ALGOS', 'DEFAULT_ROTATION',
    # encoding
    'encode_ip', 'encode_port', 'stack_string_pushes',
    # slots
    'SlotAllocator',
    # snippets
    'SNIPPET_STARTUPINFOA_SOCKET', 'SNIPPET_STARTUPINFOA_NULL', 'SNIPPET_CMD_STRING',
    'snippet_createprocessa', 'snippet_terminateprocess',
    'snippet_wsa_init', 'snippet_wsa_socket_tcp',
    'snippet_sockaddr_bind', 'snippet_bind_listen_accept', 'snippet_wsaconnect',
    # builders
    'custom_code', 'bindshell_code', 'revshell_code', 'loader_code',
    # assembler
    'assemble', 'assemble64',
]
