# Structures, Arrays, Strings, and Buffer Semantics

## Learning objectives

- Recover structure fields from repeated offsets.
- Recognize arrays from scale factors and pointer increments.
- Distinguish string copies from raw byte copies.
- Identify length, capacity, and terminator relationships.

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

## Common compiler patterns

- `[ecx+4]`, `[ecx+8]`, `[ecx+0Ch]`: structure fields.
- `[base+index*4]`: dword array, pointer array, or table.
- `mov byte ptr [edi+ecx],0`: NUL terminator at index.
- `cmp ecx, [ebp+10h]; jae fail`: leaves room for a terminator when ECX is later used as `dst[len]`.
- `rep movsb` or `_memcpy`: raw count-based copy.

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

## Reverse engineering thought process

Do not call `[esi+4]` "size" generically. Its role is proven by use:

- Compared against capacity.
- Used as `memcpy` count.
- Used as terminator index.

That makes it a string length field.

## Common mistakes

- Missing the `+1` implied by explicit terminator writes.
- Confusing source length with destination capacity.
- Assuming `memcpy` means unsafe. Safety depends on the count and destination.
- Treating a structure offset as a constant magic value.

## Exercises

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

## Challenge problems

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

## Solutions with reasoning

Exercise solution:

The scale `*8` indicates 8-byte elements. Reading `[base + index*8 + 4]` suggests
an array of structures where field `+4` is loaded from element `index`. If it
were an array of pointers, you would expect a scale of 4 followed by a second
dereference.

Plausible pseudocode:

```c
return records[i].field_4;
```

Challenge solution:

Stack offsets shift as arguments are pushed. A static listing can become
confusing if you read `[esp+0Ch]` after previous pushes as if ESP had not moved.
In IDA, normalize the prototype and inspect stack deltas; in WinDbg, break before
the call and dump `dd esp L8` to identify the actual pushed values. The semantic
goal is to prove destination, source, and count, not to memorize offsets in a
moving stack.

---
