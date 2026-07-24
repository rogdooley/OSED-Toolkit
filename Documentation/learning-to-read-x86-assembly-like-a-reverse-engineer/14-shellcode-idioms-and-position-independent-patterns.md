# Shellcode Idioms and Position-Independent Patterns

## Learning objectives

- Recognize position-independent code patterns in x86 shellcode.
- Identify `call/pop` and `fstenv`-based EIP recovery.
- Read PEB-walking sequences that resolve API addresses at runtime.
- Recognize encoder/decoder stubs and egghunter patterns.
- Distinguish shellcode idioms from normal compiler output.

## Concept discussion

Shellcode runs without the loader's help. It cannot use import tables, fixed
addresses, or relocations. Every address it needs must be derived at runtime.
That constraint produces distinctive assembly patterns a reverse engineer
should recognize on sight.

The core problems shellcode solves:

- **Where am I?** The code must learn its own address to reference embedded
  data (strings, hashes, encoded payload).
- **Where are the APIs?** Without an import table the code must walk the PEB
  to find loaded modules and resolve exports by name or hash.
- **How do I avoid bad characters?** Network protocols, string functions, and
  copy operations may filter bytes like `0x00`, `0x0A`, `0x0D`, or `0x80+`.
  Encoder stubs transform the payload to survive transit, then decode in place.
- **Where is my payload?** Staged shellcode or egghunters search memory for a
  marker tag to locate a larger payload placed elsewhere.

These are not compiler patterns. They are hand-written or tool-generated
sequences with a distinctive shape.

## Common shellcode patterns

- `call next; next: pop reg`: classic EIP recovery.
- `jmp over; tag: call back; over: ...`: call-backward variant for data reference.
- `fstenv [esp-0Ch]` followed by `pop reg`: FPU-based EIP recovery.
- `mov eax, fs:[30h]`: PEB access.
- `mov eax, [eax+0Ch]`: `PEB->Ldr`.
- `mov eax, [eax+14h]`: `InMemoryOrderModuleList`.
- `ror edx, 0Dh; add edx, [esi]`: hash accumulation for API name resolution.
- `xor byte ptr [edi], key; inc edi; loop`: single-byte XOR decoder.
- `cmp dword ptr [edi], tag; jz found; inc edi`: egghunter linear scan.
- Null-byte avoidance: `xor eax, eax` instead of `mov eax, 0`; `push byte 1`
  instead of `push 1`; `sub eax, -value` instead of `add eax, value`.

## Fully annotated example

### EIP recovery and data reference

```asm
shellcode_start:
    jmp     short get_data
callback:
    pop     esi
    ; ESI now points to the string below.
    xor     eax, eax
    mov     byte ptr [esi+0Dh], al
    push    eax
    push    esi
    call    ebp
    ; Assume EBP holds address of a resolved API.
get_data:
    call    callback
    db      "Hello, world!", 0FFh
```

Annotated:

```asm
jmp short get_data
; Skip over the callback body to reach the CALL below.

call callback
; CALL pushes the address of the next byte (the string) onto the stack, then
; jumps backward. This is not a normal function call. The return address IS the
; data pointer.

pop esi
; Pop the pushed return address. ESI now holds the runtime address of the
; embedded string.

mov byte ptr [esi+0Dh], al
; Overwrite the placeholder byte after "Hello, world!" with a NUL terminator.
; The 0xFF placeholder avoided a null byte in the shellcode body.
```

The programmer wrote position-independent data referencing. A compiler would
never emit `call` to push a data address. Seeing `call` immediately followed by
non-code bytes or a `pop` into a general-purpose register is a strong shellcode
indicator.

### PEB walk for module resolution

```asm
    xor     eax, eax
    mov     eax, fs:[eax+30h]
    mov     eax, [eax+0Ch]
    mov     esi, [eax+14h]
next_module:
    lodsb
    ; Actually: lodsd (load dword from [esi], advance esi)
    ; Corrected below.
```

Corrected and annotated PEB walk:

```asm
    xor     eax, eax
    mov     eax, fs:[eax+30h]
    ; Read the PEB pointer from the TEB. Using [eax+30h] instead of fs:[30h]
    ; avoids a null byte in the displacement encoding.

    mov     eax, [eax+0Ch]
    ; PEB->Ldr (PEB_LDR_DATA pointer).

    mov     esi, [eax+14h]
    ; Ldr->InMemoryOrderModuleList.Flink. This is a LIST_ENTRY pointing to the
    ; first loaded module's LDR_DATA_TABLE_ENTRY (at the InMemoryOrderLinks
    ; offset).

next_module:
    lodsd
    ; Load [ESI] into EAX and advance ESI by 4. EAX now holds the Flink of the
    ; next list entry.

    xchg    esi, eax
    ; Move to the next entry. ESI = new list node.

    mov     ebx, [esi+10h]
    ; DllBase of this module (base address of the loaded image).
```

The reverse engineer sees `fs:[30h]` and knows this is PEB access. The
`0Ch -> 14h -> lodsd` chain is the standard module-list walk. Variations exist
with `InLoadOrderModuleList` (offset `0Ch` instead of `14h`) or
`InInitializationOrderModuleList` (offset `1Ch`).

## Reverse engineering thought process

When you encounter code that does not look like compiler output, ask:

```text
EIP recovery method: call/pop, fstenv, or other
Data references: relative to recovered EIP?
PEB access: fs:[30h] present?
Module walk: which list order?
API resolution: hash-based or string-based?
Encoder: XOR, ADD, SUB, or multi-byte?
Egg tag: 4-byte or 8-byte marker?
Null avoidance: which techniques?
```

Shellcode is sequential: it does not have the call graph of compiled code. Walk
it linearly and mark each phase boundary (decoder, resolver, payload).

## Common mistakes

- Treating `call/pop` as a function call and trying to analyze the "callee."
- Missing `fstenv`-based EIP recovery because FPU instructions look unrelated.
- Assuming `fs:[30h]` is SEH-related. SEH uses `fs:[0]`, not `fs:[30h]`.
- Stopping at the decoder stub and missing the real payload underneath.
- Treating encoded bytes as data when they are code that has not been decoded yet.
- Confusing the egg tag with a magic constant or structure signature.

## Exercises

```asm
    xor     ecx, ecx
    mov     ecx, fs:[ecx+30h]
    mov     ecx, [ecx+0Ch]
    mov     ecx, [ecx+14h]
    mov     ecx, [ecx]
    mov     ecx, [ecx]
    mov     ebx, [ecx+10h]
```

Questions:

- What data structure is being traversed?
- Why does `mov ecx, [ecx]` appear twice?
- What does EBX hold at the end?
- Which module does this target and why?

## Challenge problems

```asm
decoder:
    mov     edi, esi
    xor     ecx, ecx
    mov     cl, 38h
decode_loop:
    xor     byte ptr [edi], 0AAh
    inc     edi
    loop    decode_loop
    jmp     esi
```

Assume ESI was set by a prior `call/pop`. Explain:

- What transformation is applied?
- How many bytes are decoded?
- Why does execution jump to ESI after decoding?
- What must be true about the encoded payload for this to work?
- How would you extract the decoded payload statically?

## Solutions with reasoning

Exercise solution:

The sequence walks the PEB module list. `fs:[ecx+30h]` reads the PEB pointer
(using `ecx` as a zeroed base to avoid null bytes). `[PEB+0Ch]` is `Ldr`.
`[Ldr+14h]` is `InMemoryOrderModuleList.Flink`, pointing to the first module
entry. Each `mov ecx, [ecx]` follows the `Flink` to the next entry, so two
iterations skip past the first two modules. On Windows, the standard load order
in `InMemoryOrderModuleList` is:

1. The executable itself
2. `ntdll.dll`
3. `kernel32.dll`

Two Flink traversals reach the third entry, which is typically `kernel32.dll`.
`[ecx+10h]` reads the `DllBase` field, so EBX holds the base address of
`kernel32.dll`. This is the setup for export-table walking to resolve API
functions like `WinExec`, `LoadLibraryA`, or `GetProcAddress`.

Challenge solution:

The decoder XORs each byte at `[edi]` with `0xAA` for `0x38` (56) bytes
starting at the address in ESI. The `loop` instruction decrements ECX and
jumps while nonzero. After decoding, `jmp esi` transfers execution to the
now-decoded payload. The decoder is a single-byte XOR stub.

For this to work, the encoded payload must not contain the byte `0xAA` XORed
with any of the decoder's own bytes (or the decoder must be placed outside the
decoded region, which it is here since ESI points past the decoder). The
payload also must not contain bytes that, after XOR with `0xAA`, produce
characters filtered by the delivery channel.

To extract the decoded payload statically, XOR each of the 56 bytes starting
at the address after the `jmp esi` with `0xAA`. In Python:

```python
decoded = bytes(b ^ 0xAA for b in encoded_payload[:0x38])
```

Or in WinDbg, break at the `jmp esi` instruction and dump the decoded payload
with `db esi L38`.

---
