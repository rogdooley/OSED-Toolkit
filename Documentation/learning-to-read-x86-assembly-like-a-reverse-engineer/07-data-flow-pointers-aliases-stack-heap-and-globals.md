# Data Flow: Pointers, Aliases, Stack, Heap, and Globals

## Learning objectives

- Track value origin and destination through registers and memory.
- Recognize pointer propagation and aliases.
- Distinguish stack, heap, global, and imported storage.
- Identify when two names may refer to the same memory.

## Concept discussion

Data flow is the spine of reverse engineering. Control flow tells you which path
runs. Data flow tells you what that path means.

A pointer copied from EAX to ESI to `[ebp-4]` is still the same pointer unless an
instruction changes it. A buffer passed into `memcpy` becomes important because
the write destination and count define risk. A global read can be configuration,
state, a function table, or a security-sensitive flag.

Reverse engineers care less about variable names than about provenance:

- user input
- parsed input
- validated input
- trusted configuration
- heap allocation
- local stack temporary
- global process state
- imported function pointer

## Common compiler patterns

- `mov esi, [ebp+8]`: keep argument pointer in callee-saved register.
- `mov [ebp-4], eax`: spill a temporary or preserve a value across a call.
- `call _malloc; test eax,eax`: heap allocation and null check.
- `mov eax, ds:g_config`: global read.
- `mov [ecx+offset], eax`: structure field write through pointer.

## Fully annotated example

```asm
sub_401600:
    push    ebp
    mov     ebp, esp
    push    esi
    mov     esi, [ebp+8]
    push    [ebp+0Ch]
    call    _malloc
    add     esp, 4
    test    eax, eax
    jz      fail
    mov     [esi+8], eax
    mov     ecx, [ebp+0Ch]
    mov     [esi+0Ch], ecx
    xor     eax, eax
    pop     esi
    pop     ebp
    retn
fail:
    mov     eax, 0FFFFFFFFh
    pop     esi
    pop     ebp
    retn
```

Annotated:

```asm
mov esi, [ebp+8]
; First argument is a destination object pointer.

push [ebp+0Ch] / call _malloc
; Allocate size from second argument.

test eax,eax / jz fail
; Allocation failure check.

mov [esi+8], eax
; Store heap pointer into object field +8.

mov ecx, [ebp+0Ch]
mov [esi+0Ch], ecx
; Store size into object field +0x0C.
```

The function initializes two fields: buffer pointer and buffer size. The
programmer assumes the object pointer is valid. The compiler assumes the size
argument is already suitable for `malloc`; no range check appears here.

## Reverse engineering thought process

Build a provenance table:

| Value | Origin | Destination | Meaning |
|-------|--------|-------------|---------|
| `[ebp+8]` | caller | ESI, stores at offsets | object pointer |
| `[ebp+0Ch]` | caller | malloc, `[object+0Ch]` | allocation size |
| EAX after malloc | heap allocator | `[object+8]` | heap buffer |

Then ask exploit questions: Can size be huge? Can object be fake? Is there later
copying into `[object+8]` using `[object+0Ch]`?

## Common mistakes

- Losing track of aliases after a pointer is copied.
- Assuming stack memory is safe and heap memory is unsafe; storage class is not
  trust.
- Treating globals as constants without checking writes.
- Ignoring size fields stored next to pointers.

## Exercises

```asm
sub_401650:
    mov     eax, [esp+4]
    mov     ecx, ds:g_table
    mov     edx, [eax+4]
    mov     [ecx+edx*4], eax
    xor     eax, eax
    retn
```

Questions:

- What data flows into the global table?
- Which field controls the index?
- What trust questions follow?

## Challenge problems

```asm
sub_401680:
    mov     eax, [esp+4]
    mov     ecx, [eax+8]
    push    ecx
    call    _free
    add     esp, 4
    mov     dword ptr [eax+8], 0
    retn
```

Find the aliasing bug in the analyst's reasoning, not necessarily in the program.

## Solutions with reasoning

Exercise solution:

The first argument pointer is stored into a global table. The index comes from
the dword field at offset `+4` inside that object. If the object or field is
attacker-controlled, this may become an out-of-bounds global write or pointer
registration primitive.

Plausible pseudocode:

```c
g_table[obj->id] = obj;
```

Challenge solution:

After `_free`, EAX is caller-saved and cannot be assumed to still hold the
original object pointer. The final `mov [eax+8],0` is suspicious because the
compiler would normally preserve the object pointer across a call if it needed
it. Either the snippet is hand-written/incorrectly lifted, there was an unshown
preservation instruction, or the compiler inlined `_free` in a link-time
optimized build and the inlined body happens not to clobber EAX. The last case
is real but dangerous to rely on: observed behavior is not the same as an ABI
guarantee. The reverse engineering lesson: do not assume caller-saved registers
survive calls, even when a particular build appears to preserve them.

---
