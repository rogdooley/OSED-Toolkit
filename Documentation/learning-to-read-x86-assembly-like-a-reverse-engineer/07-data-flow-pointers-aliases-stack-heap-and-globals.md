# 7. Data Flow: Pointers, Aliases, Stack, Heap, and Globals

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

### Taint tracking for exploit analysis

In exploit-oriented reversing, data flow becomes **taint tracking**: which
values originate from attacker-controlled input?

Mark values as tainted when they come from:
- `recv`, `ReadFile`, `fread` return buffers
- Command-line arguments, environment variables
- Registry values, file contents, network data
- Any parsed field derived from tainted input

Taint propagates through:
- Register copies (`mov eax, tainted_reg`)
- Arithmetic (`add eax, tainted_reg` -- result is tainted)
- Memory stores (`mov [ptr], tainted_reg` -- memory location is tainted)
- Function arguments (`push tainted_reg; call func` -- callee receives taint)

Taint is killed by:
- Overwrite with a constant (`mov eax, 0`)
- Overwrite with a trusted value (`mov eax, [trusted_global]`)
- Validation that constrains the value to a safe range

The exploit question is always: can tainted data reach a security-sensitive
operation (copy count, write destination, function pointer, return address)
without passing through a correct validation gate?

## Exercises

### Exercise 1

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

### Exercise 2

```asm
sub_401690:
    push    ebp
    mov     ebp, esp
    push    esi
    mov     esi, [ebp+8]
    push    100h
    call    _malloc
    add     esp, 4
    test    eax, eax
    jz      short fail
    mov     [esi+0Ch], eax
    mov     dword ptr [esi+10h], 100h
    push    [esi+10h]
    push    [ebp+0Ch]
    push    eax
    call    _memcpy
    add     esp, 0Ch
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

Questions:

- What is the provenance of the memcpy destination?
- What is the provenance of the memcpy source?
- Is this copy safe? What determines safety?
- Build a provenance table for all values.

### Exercise 3

```asm
sub_4016D0:
    mov     eax, [esp+4]
    mov     ecx, [eax]
    mov     edx, [ecx+4]
    mov     [eax+8], edx
    mov     ecx, [eax]
    mov     ecx, [ecx]
    mov     [eax], ecx
    retn
```

Questions:

- How many levels of indirection does this function follow?
- What does the function appear to do? (Hint: think linked list.)
- Draw the pointer relationships before and after the function runs.

## Challenge problems

### Challenge 1

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

### Challenge 2

```asm
sub_4016F0:
    push    esi
    mov     esi, [esp+8]
    mov     eax, ds:g_callback
    test    eax, eax
    jz      short no_cb
    push    esi
    call    eax
    add     esp, 4
no_cb:
    mov     eax, [esi+4]
    mov     ds:g_last_result, eax
    pop     esi
    retn
```

Two global variables are used. One controls an indirect call. The other receives
data. If an attacker can write to the process's data section, which global is
more dangerous and why?

## Solutions with reasoning

### Exercise 1 solution

The first argument pointer is stored into a global table. The index comes from
the dword field at offset `+4` inside that object. If the object or field is
attacker-controlled, this may become an out-of-bounds global write or pointer
registration primitive.

Plausible pseudocode:

```c
g_table[obj->id] = obj;
```

### Exercise 2 solution

Provenance table:

| Value | Origin | Destination | Meaning |
|-------|--------|-------------|---------|
| `[ebp+8]` | caller | ESI | object pointer |
| `[ebp+0Ch]` | caller | memcpy source | source buffer |
| EAX (malloc) | heap allocator | `[esi+0Ch]` | heap buffer |
| 0x100 | constant | `[esi+10h]`, memcpy count | capacity and copy count |

The memcpy destination is a freshly allocated 256-byte heap buffer. The source
is the caller's second argument. The count is hardcoded at 0x100, matching the
allocation. The copy is safe in isolation: count == capacity. However, if the
source buffer (`[ebp+0Ch]`) contains fewer than 256 valid bytes, the copy may
read past the source, and if other code later writes to `[esi+0Ch]` using a
different count, the fixed capacity becomes a constraint.

### Exercise 3 solution

The function follows two levels of indirection. Let `ptr = [esp+4]`:
- `[ptr]` is a pointer to a node (call it `node`).
- `[node+4]` is a data field copied to `[ptr+8]`.
- `[node]` (the Flink/next pointer) replaces `[ptr]`.

This is a linked list dequeue operation: it removes the head node, saves a
field from it, and advances the head pointer. Before: `ptr -> node -> next`.
After: `ptr -> next`, and `ptr+8` holds `node->field_4`.

### Challenge 1 solution

After `_free`, EAX is caller-saved and cannot be assumed to still hold the
original object pointer. The final `mov [eax+8],0` is suspicious because the
compiler would normally preserve the object pointer across a call if it needed
it. Either the snippet is hand-written/incorrectly lifted, there was an unshown
preservation instruction, or the compiler inlined `_free` in a link-time
optimized build and the inlined body happens not to clobber EAX. The last case
is real but dangerous to rely on: observed behavior is not the same as an ABI
guarantee. The reverse engineering lesson: do not assume caller-saved registers
survive calls, even when a particular build appears to preserve them.

### Challenge 2 solution

`g_callback` is far more dangerous. It controls an indirect call (`call eax`),
so overwriting it gives arbitrary code execution -- the attacker sets
`g_callback` to a shellcode address or ROP pivot, and the next time this
function runs with a non-null callback, execution jumps there.

`g_last_result` receives data but is not used for control flow in this function.
Corrupting it might influence later logic, but that requires a second-order
effect. Corrupting `g_callback` is a direct, single-step path to code execution.

This illustrates the taint tracking priority: global function pointers and
callback addresses are higher-priority targets than global data variables.

## Key takeaways

- Data flow is the spine of exploit analysis. Control flow tells you which
  path runs; data flow tells you whether attacker input reaches a dangerous
  operation.

- Build provenance tables: track where each value came from, where it goes,
  and what it means. Distinguish stack locals, heap allocations, globals, and
  imported state.

- Taint tracking is data flow with a security lens. Mark attacker-controlled
  values and follow them through copies, arithmetic, and function calls until
  they reach a security-sensitive operation or are validated.

- Pointer aliases are the primary source of analyst error. When a pointer is
  copied into a callee-saved register, it survives calls. When it stays in a
  caller-saved register (EAX, ECX, EDX), it may be clobbered.

- Global function pointers and callback addresses are high-priority exploit
  targets. Corrupting one gives direct code execution without needing to
  reach a return instruction.

## See also

- `x86-osed-assembly-reference/03-memory-operands-and-addressing-modes.md` --
  addressing mode mechanics
- `x86-osed-assembly-reference/09-calling-conventions-and-abi.md` -- register
  preservation rules
- `osed-reversing-guide/07-data-flow.md` -- data flow tracing methodology
- `osed-reversing-guide/08-aggregates-and-memory.md` -- pointer and structure
  analysis
- `DRILLS/dataflow.md` -- data flow tracing practice drills

---
