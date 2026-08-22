# 8. Structures, Arrays, Strings, and Buffer Semantics

## Learning objectives

- Recover structure fields from repeated offsets.
- Recognize arrays from scale factors and pointer increments.
- Distinguish string copies from raw byte copies.
- Identify length, capacity, and terminator relationships.
- Recover a full struct layout from disassembly across multiple functions.
- Recognize Windows-internal structures (UNICODE_STRING, etc.) by access pattern.
- Spot off-by-one terminator bugs -- the most common OSED buffer overflow class.

## Concept discussion

Structures reveal themselves through stable offsets. Arrays reveal themselves
through repeated element size. Strings reveal themselves through sentinel checks
or explicit NUL writes.

The core semantic question is not "what is the C type?" It is:

- Which bytes belong together?
- Which value says how many bytes are valid?
- Which value says how many bytes fit?
- Which operation writes a terminator?
- Does the check cover all bytes written?

### Length vs. capacity -- why this distinction matters

Every stack overflow in OSED reduces to one failure: the programmer confused
length with capacity, or failed to compare one against the other.

- **Length** is "how many bytes are currently valid in this buffer."
- **Capacity** is "how many bytes can this buffer hold."
- **Terminator cost** is the extra byte (or two, for wide strings) needed after
  the valid data.

A correct bounded copy looks like this:

```text
if (length < capacity)      // strictly less -- leaves room for NUL
    memcpy(dst, src, length);
    dst[length] = 0;
```

A vulnerable copy uses `<=` instead of `<`:

```text
if (length <= capacity)     // allows length == capacity
    memcpy(dst, src, length);
    dst[length] = 0;        // writes one byte past the buffer
```

Or omits the comparison entirely:

```text
memcpy(dst, src, length);   // no check at all
```

In assembly, the distinction is a single instruction difference -- `jae` (unsigned
>=, rejecting length >= capacity) versus `ja` (unsigned >, rejecting only
length > capacity). Miss it and you miss the bug.

### ANSI vs. wide strings

Windows uses two string encodings everywhere:

- **ANSI (char)**: one byte per character, NUL terminated with a single 0x00.
- **Wide (wchar_t)**: two bytes per character (UTF-16LE), NUL terminated with
  0x0000 (two zero bytes).

The assembly tells you which one you are looking at:

```asm
; ANSI string access -- byte-sized element
movzx eax, byte ptr [ecx+edx]      ; scale factor *1 (implicit)

; Wide string access -- word-sized element
movzx eax, word ptr [ecx+edx*2]    ; scale factor *2
```

Wide strings double every size calculation. A buffer that holds 128 ANSI
characters holds only 64 wide characters. Confusing byte count with character
count is a classic source of overflows in Windows code.

## Common compiler patterns

- `[ecx+4]`, `[ecx+8]`, `[ecx+0Ch]`: structure fields.
- `[base+index*4]`: dword array, pointer array, or table.
- `[base+index*2]`: word array or wide-character string.
- `mov byte ptr [edi+ecx],0`: NUL terminator at index (ANSI).
- `mov word ptr [edi+ecx*2],0`: NUL terminator at index (wide).
- `cmp ecx, [ebp+10h]; jae fail`: leaves room for a terminator when ECX is later used as `dst[len]`.
- `rep movsb` or `_memcpy`: raw count-based copy.
- `rep movsw` or `rep movsd`: word/dword-granularity copy (check element count vs byte count).

## Fully annotated example

```asm
sub_401700:
    push    ebp
    mov     ebp, esp
    push    esi
    push    edi
    mov     esi, [ebp+8]
    mov     ecx, [esi+4]
    cmp     ecx, [ebp+10h]
    jae     fail
    mov     edi, [ebp+0Ch]
    push    ecx
    push    [esi+8]
    push    edi
    call    _memcpy
    add     esp, 0Ch
    mov     byte ptr [edi+ecx], 0
    xor     eax, eax
    pop     edi
    pop     esi
    pop     ebp
    retn
fail:
    mov     eax, 0FFFFFFFFh
    pop     edi
    pop     esi
    pop     ebp
    retn
```

Annotated:

```asm
mov esi, [ebp+8]
; Record pointer.

mov ecx, [esi+4]
; Field +4 is a length.

cmp ecx, [ebp+10h] / jae fail
; Require length < destination capacity. Strictly less leaves room for NUL.

mov edi, [ebp+0Ch]
; Destination pointer.

push ecx / push [esi+8] / push edi / call _memcpy
; Copy record->data, length bytes, into destination.

mov byte ptr [edi+ecx], 0
; Terminate string after copied bytes.
```

The programmer wrote "copy record text into a caller buffer if it fits." The
compiler exposes a three-field relationship: source record, destination pointer,
destination capacity.

Stack layout at the memcpy call:

```text
+----------+-------------------+
| ebp+10h  | capacity (arg3)   |
+----------+-------------------+
| ebp+0Ch  | dst pointer (arg2)|
+----------+-------------------+
| ebp+08h  | record ptr (arg1) |
+----------+-------------------+
| ebp+04h  | return address    |
+----------+-------------------+
| ebp      | saved ebp         |
+----------+-------------------+

Record layout (pointed to by esi):
+--------+-----------+
| +0x00  | (unknown) |
+--------+-----------+
| +0x04  | length    |
+--------+-----------+
| +0x08  | data ptr  |
+--------+-----------+
```

## Reverse engineering thought process

Do not call `[esi+4]` "size" generically. Its role is proven by use:

- Compared against capacity.
- Used as `memcpy` count.
- Used as terminator index.

That makes it a string length field.

## Structure recovery

Structures in real binaries are not labeled. You must recover them from
observation: every access through a base pointer tells you one field's offset
and width.

### Worked example: recovering a struct from disassembly

Suppose you see these accesses across three functions, all using the same base
pointer (call it `ptr`):

Function A (initialization):

```asm
mov     dword ptr [eax], 1          ; +0x00, dword write
mov     word ptr [eax+4], 0         ; +0x04, word write
mov     dword ptr [eax+8], ecx      ; +0x08, dword write (pointer from ecx)
mov     byte ptr [eax+0Ch], 0       ; +0x0C, byte write
```

Function B (processing):

```asm
cmp     dword ptr [esi], 2          ; +0x00, dword read (compared to constant)
jnz     skip
mov     edx, [esi+8]               ; +0x08, dword read (used as pointer below)
movzx   ecx, byte ptr [edx]        ; dereferences +0x08 as a pointer
movzx   eax, byte ptr [esi+0Ch]    ; +0x0C, byte read
```

Function C (cleanup):

```asm
movzx   eax, word ptr [edi+4]      ; +0x04, word read
test    eax, eax
jz      done
push    dword ptr [edi+8]          ; +0x08, dword (passed to free -- confirms pointer)
call    _free
```

**Step 1: Collect all offsets and access sizes.**

```text
Offset   Size    Evidence
+0x00    dword   written as 1, compared to 2 -- looks like a type/state field
+0x04    word    written as 0, read and tested -- flag or count
+0x06    --      gap (no access) -- likely padding
+0x08    dword   written from register, dereferenced, passed to free -- pointer
+0x0C    byte    written as 0, read later -- flag or single-char field
```

**Step 2: Determine padding from gaps.**

Between +0x04 (word, 2 bytes) and +0x08 (dword), there is a 2-byte gap at +0x06.
MSVC aligns dwords to 4-byte boundaries by default, so this gap is compiler
padding.

**Step 3: Build the struct.**

```c
struct recovered_t {       // Total size: 0x10 (16 bytes, with tail padding)
    DWORD  type;           // +0x00  state or type discriminator
    WORD   flags;          // +0x04  flag or reference count
    // 2 bytes padding     // +0x06
    BYTE  *data;           // +0x08  heap-allocated buffer
    BYTE   status;         // +0x0C  single-byte status
    // 3 bytes padding     // +0x0D  (tail padding to align struct size)
};
```

**Step 4: Verify in IDA.**

In IDA, you can formalize this: Structures window (Shift+F9) -> Add struct ->
define each field at its offset. Once defined, apply the struct type to the
base pointer and all field accesses become named.

### Verify in WinDbg

If you have the struct base address at runtime:

```text
0:000> dd <addr> L4
<addr>  00000001 00000000 0040B230 00000000

0:000> dt ntdll!_UNICODE_STRING <addr>   ; for known Windows structs
```

For unknown structs, dump raw bytes and cross-reference with your offset table:

```text
0:000> db <addr> L10
<addr>  01 00 00 00 00 00 00 00-30 B2 40 00 00 00 00 00
         ^dword=1   ^word=0 ^pad  ^pointer      ^byte=0 ^pad
```

## UNICODE_STRING recognition

The `UNICODE_STRING` structure is everywhere in Windows internals -- kernel
objects, registry paths, file names, driver communication. Recognizing it on
sight saves significant reversing time.

The structure definition:

```c
typedef struct _UNICODE_STRING {
    USHORT Length;           // +0x00  current byte length (not including NUL)
    USHORT MaximumLength;   // +0x02  buffer capacity in bytes
    PWSTR  Buffer;          // +0x04  pointer to wide-char data
} UNICODE_STRING;
```

In assembly, the access pattern is distinctive:

```asm
; Typical UNICODE_STRING read sequence
mov     cx, [eax]           ; +0x00: Length (word -- bytes, not chars)
mov     dx, [eax+2]         ; +0x02: MaximumLength (word)
mov     edi, [eax+4]        ; +0x04: Buffer pointer (dword)
```

Key observations:

- Length and MaximumLength are in **bytes**, not characters. Divide by 2 for
  character count.
- The Buffer is a wide string (UTF-16LE), so character access uses `*2` scaling.
- MaximumLength is typically Length + 2 (room for one wide NUL).
- Many Windows API functions (RtlCopyUnicodeString, RtlInitUnicodeString, etc.)
  operate on this structure.

### Verify in WinDbg

```text
0:000> dt ntdll!_UNICODE_STRING <addr>
   +0x000 Length           : 0x1a
   +0x002 MaximumLength    : 0x1c
   +0x004 Buffer           : 0x00abcdef  "C:\Windows\System32"

0:000> du poi(<addr>+4)       ; dump wide string from Buffer field
00abcdef  "C:\Windows\System32"
```

## Common mistakes

- Missing the `+1` implied by explicit terminator writes.
- Confusing source length with destination capacity.
- Assuming `memcpy` means unsafe. Safety depends on the count and destination.
- Treating a structure offset as a constant magic value.
- Confusing byte count with character count in wide-string operations.
- Assuming padding bytes are meaningful fields.

## Exercises

### Exercise 1: Array element access

```asm
sub_401760:
    mov     eax, [esp+4]
    mov     ecx, [esp+8]
    mov     edx, [eax+ecx*8+4]
    retn
```

Questions:

- What is the apparent element size?
- Is this an array of structures or an array of pointers?
- What field is being read?

### Exercise 2: UNICODE_STRING manipulation

```asm
sub_4017A0:
    push    esi
    mov     esi, [esp+8]       ; arg1: UNICODE_STRING pointer?
    movzx   eax, word ptr [esi]
    movzx   ecx, word ptr [esi+2]
    sub     ecx, eax
    cmp     ecx, 4
    jb      too_small
    mov     edx, [esi+4]
    shr     eax, 1
    mov     word ptr [edx+eax*2], 41h   ; 'A' in UTF-16LE
    mov     word ptr [edx+eax*2+2], 0   ; wide NUL
    add     word ptr [esi], 2
    xor     eax, eax
    pop     esi
    retn
too_small:
    mov     eax, 0FFFFFFFFh
    pop     esi
    retn
```

Questions:

- Is this a UNICODE_STRING? What evidence confirms it?
- What operation does this function perform?
- Is the bounds check correct? Does it account for the wide NUL terminator?

### Exercise 3: Wide vs. ANSI string loop

```asm
; Snippet A
loop_a:
    movzx   eax, byte ptr [esi+ecx]
    mov     [edi+ecx], al
    inc     ecx
    test    al, al
    jnz     loop_a

; Snippet B
loop_b:
    movzx   eax, word ptr [esi+ecx*2]
    mov     [edi+ecx*2], ax
    inc     ecx
    test    ax, ax
    jnz     loop_b
```

Questions:

- Which snippet handles ANSI strings and which handles wide strings?
- What is the termination condition for each?
- If the destination buffer is 256 bytes, how many characters can each loop
  safely copy (excluding NUL)?

## Challenge problems

### Challenge 1: Stack offset confusion

```asm
sub_401790:
    mov     ecx, [esp+0Ch]
    cmp     ecx, [esp+10h]
    ja      fail
    push    ecx
    push    [esp+0Ch]
    push    [esp+0Ch]
    call    _memcpy
    add     esp, 0Ch
    xor     eax, eax
    retn
fail:
    mov     eax, 0FFFFFFFFh
    retn
```

Do not trust the apparent stack offsets after pushes. Explain how you would
verify the real arguments.

### Challenge 2: Off-by-one terminator overflow

```asm
sub_401800:
    push    ebp
    mov     ebp, esp
    sub     esp, 100h
    mov     ecx, [ebp+0Ch]      ; length argument
    cmp     ecx, 100h
    ja      fail
    lea     edx, [ebp-100h]     ; local buffer, 256 bytes
    push    ecx
    push    [ebp+8]             ; source pointer
    push    edx
    call    _memcpy
    add     esp, 0Ch
    mov     ecx, [ebp+0Ch]
    mov     byte ptr [ebp+ecx-100h], 0  ; NUL terminate
    xor     eax, eax
    mov     esp, ebp
    pop     ebp
    retn
fail:
    mov     eax, 0FFFFFFFFh
    mov     esp, ebp
    pop     ebp
    retn
```

Identify the exact vulnerability. What single byte gets overwritten and what
does it overwrite? Draw the stack layout.

## Solutions with reasoning

### Exercise 1 solution

The scale `*8` indicates 8-byte elements. Reading `[base + index*8 + 4]` suggests
an array of structures where field `+4` is loaded from element `index`. If it
were an array of pointers, you would expect a scale of 4 followed by a second
dereference.

Plausible pseudocode:

```c
return records[i].field_4;
```

### Exercise 2 solution

Yes, this is a UNICODE_STRING. The evidence:

- `[esi]` is read as a word (Length in bytes).
- `[esi+2]` is read as a word (MaximumLength in bytes).
- `[esi+4]` is read as a dword (Buffer pointer).
- Length is divided by 2 (`shr eax, 1`) to convert bytes to character index.
- Character access uses `*2` scaling for wide characters.

The function appends a single wide character 'A' (0x0041) at the current end of
the string, writes a wide NUL after it, and increments Length by 2 (one wide
character = 2 bytes).

The bounds check verifies that `MaximumLength - Length >= 4`, which accounts for
the 2-byte character plus the 2-byte wide NUL. The check is correct.

### Exercise 3 solution

Snippet A is ANSI: byte-sized access (`byte ptr`), no scale factor, tests `al`
(single byte) for zero.

Snippet B is wide: word-sized access (`word ptr`), `*2` scale factor, tests `ax`
(two bytes) for zero.

For a 256-byte destination:
- ANSI: 255 characters (256 bytes minus 1 for NUL).
- Wide: 127 characters (256 bytes / 2 = 128 wide chars, minus 1 for wide NUL).

Neither loop has a length check, so both will overflow the destination if the
source string is too long.

### Challenge 1 solution

Stack offsets shift as arguments are pushed. A static listing can become
confusing if you read `[esp+0Ch]` after previous pushes as if ESP had not moved.
In IDA, normalize the prototype and inspect stack deltas; in WinDbg, break before
the call and dump `dd esp L8` to identify the actual pushed values. The semantic
goal is to prove destination, source, and count, not to memorize offsets in a
moving stack.

Also note: the comparison uses `ja` (unsigned above), not `jae`. This means it
allows `ecx == [esp+10h]`, which would be length == capacity. If a terminator is
written after the copy, this is an off-by-one bug.

### Challenge 2 solution

The vulnerability is an off-by-one overflow. The check is `cmp ecx, 100h / ja`,
which allows `ecx == 0x100` (256). The buffer at `[ebp-100h]` is exactly 256
bytes. When `ecx == 0x100`:

- `memcpy` copies 256 bytes into the 256-byte buffer -- fills it exactly.
- The NUL terminator writes to `[ebp + 0x100 - 0x100]` = `[ebp]`, which is the
  saved EBP.

```text
Stack layout:
+----------+-------------------+
| ebp+0Ch  | length argument   |
+----------+-------------------+
| ebp+08h  | source pointer    |
+----------+-------------------+
| ebp+04h  | return address    |
+----------+-------------------+
| ebp+00h  | saved EBP  <---- overwritten with 0x00  |
+----------+-------------------+
| ebp-01h  | buffer[255]       |
|   ...    |    ...            |
| ebp-100h | buffer[0]         |
+----------+-------------------+
```

The low byte of saved EBP is zeroed. This corrupts the caller's frame pointer,
which can lead to a controlled write or controlled return address in the caller's
epilogue. This is the classic "one-byte EBP overwrite" technique.

The fix: change `ja` to `jae`, or equivalently check `cmp ecx, 0FFh / ja`,
ensuring length < capacity so the NUL byte always lands inside the buffer.

## Key takeaways

- Structures are recovered by collecting offsets, access widths, and usage
  patterns across multiple functions -- not from any single instruction.
- Length vs. capacity is the single most important distinction for OSED exploit
  analysis. `<` is safe for NUL-terminated copies; `<=` is usually a bug.
- Wide strings (wchar_t / UTF-16LE) double every size calculation. Watch for
  `*2` scale factors and `word ptr` accesses.
- UNICODE_STRING (+0x00 Length, +0x02 MaximumLength, +0x04 Buffer) appears
  throughout Windows internals -- recognize it by its three-field access pattern.
- Off-by-one terminator bugs are subtle (one instruction difference) but directly
  exploitable through saved EBP corruption.

## See also

- `x86-osed-assembly-reference/` chapters 03 (memory operands), 11 (buffers and
  stack overflows), 22 (format string assembly concepts)
- `osed-reversing-guide/` chapters 08 (aggregates and memory), 10 (buffers and
  offsets)
- `DRILLS/structure_recovery.md` -- practice recovering structs from disassembly
- `DRILLS/stack_overflow.md` -- off-by-one and unbounded copy drills

---
