# 6. Switches, Jump Tables, Tail Calls, and Thunks

## Learning objectives

- Recognize switch lowering and jump tables.
- Distinguish dispatcher logic from handler logic.
- Identify tail calls and import thunks.
- Treat indirect branches as control-flow data flow.

## Concept discussion

Dispatch code often exists to route work, not to perform the work. A reverse
engineer should avoid spending too long inside scaffolding once the dispatch key,
range check, and targets are understood.

Switch statements can lower into:

- Compare chains for sparse cases.
- Jump tables for dense cases.
- Lookup tables plus indirect calls.
- Tail calls when the wrapper simply forwards control.

The CPU is answering: "Given this key, which code address should execute next?"

## Common compiler patterns

- `cmp eax, max; ja default; jmp dword ptr [table+eax*4]`: dense switch.
- `jmp _ImportedFunction`: import thunk.
- `call dword ptr [ecx+offset]`: callback, method, or function pointer field.
- `jmp target` at function end: tail call.
- `mov ecx, this; call dword ptr [eax+N]`: virtual function call pattern.

## Fully annotated example

```asm
sub_401500:
    mov     eax, [esp+8]
    cmp     eax, 2
    ja      default
    jmp     dword ptr ds:off_402000[eax*4]
case0:
    jmp     handle_ping
case1:
    jmp     handle_echo
case2:
    jmp     handle_copy
default:
    mov     eax, 0FFFFFFFFh
    retn
```

Annotated:

```asm
mov eax, [esp+8]
; Dispatch key, likely opcode or enum.

cmp eax, 2 / ja default
; Unsigned range check: only 0, 1, 2 are valid table indexes.

jmp [table+eax*4]
; Indirect branch through a dword table of code addresses.

jmp handle_*
; Tail jump to handler. The dispatcher does not return through these blocks.
```

The programmer likely wrote a switch over an opcode. The compiler assumes the
range check protects the table access. The reverse engineer should now analyze
the handlers, not overfit the dispatcher.

## Reverse engineering thought process

Recover dispatch in this order:

1. Identify the dispatch key.
2. Identify the valid range.
3. Enumerate targets.
4. Determine whether targets are calls or tail jumps.
5. Walk the target that receives attacker-controlled data.

## Common mistakes

- Treating jump-table data as code.
- Missing the unsigned range check that protects the table.
- Thinking a tail call returns to the dispatcher.
- Assuming indirect call means virtual function without checking object shape.

### Linked list traversal

Windows internal structures frequently use linked lists (doubly-linked
`LIST_ENTRY` structures). The traversal pattern appears as a loop that follows
pointers rather than incrementing an index:

```asm
    mov     esi, [start]          ; head of list
traverse:
    cmp     esi, [start]          ; back to head? (circular list)
    jz      short done
    ; process node at ESI
    mov     eax, [esi+8]          ; read a field from the node
    ; ... use eax ...
    mov     esi, [esi]            ; follow Flink (next pointer at offset 0)
    jmp     short traverse
done:
```

This pattern is critical in PEB walking (chapter 14), where shellcode traverses
`InMemoryOrderModuleList` to find loaded DLLs. The key identifier: the loop
advances by dereferencing the current pointer (`mov esi, [esi]`) instead of
adding a fixed stride.

### Register preservation across calls

When analyzing dispatch code, know which registers survive function calls:

```text
Callee-saved (preserved):  EBX, ESI, EDI, EBP
Caller-saved (clobbered):  EAX, ECX, EDX
```

If a function loads a dispatch key into EAX, calls a helper, then uses EAX
afterward, the value in EAX is the helper's return value -- not the original
dispatch key. But if the key was loaded into ESI before the call, ESI still
holds the key afterward.

This matters for exploit analysis: when a pointer is stored in a caller-saved
register and survives a call, either the callee happens not to clobber it
(unreliable) or the compiler knows the callee's register usage (link-time
optimization). Do not assume survival without evidence.

## Exercises

### Exercise 1

```asm
sub_401560:
    mov     ecx, [esp+4]
    mov     eax, [ecx]
    push    [esp+8]
    call    dword ptr [eax+0Ch]
    retn
```

Questions:

- What is the likely role of `[ecx]`?
- What is at `[eax+0Ch]`?
- Which value controls the indirect call target?

### Exercise 2

```asm
sub_401580:
    mov     eax, [esp+4]
    sub     eax, 10h
    cmp     eax, 4
    ja      short default_case
    jmp     dword ptr ds:table_402100[eax*4]
case_10:
    push    [esp+8]
    call    handler_A
    add     esp, 4
    retn
case_11:
    push    [esp+8]
    call    handler_B
    add     esp, 4
    retn
default_case:
    xor     eax, eax
    retn
```

Questions:

- What range of input values does this switch handle?
- Why does the code subtract 0x10 before the range check?
- Which handler is called for input value 0x12?

### Exercise 3

```asm
sub_4015C0:
    push    esi
    mov     esi, [esp+8]
next:
    test    esi, esi
    jz      short done
    push    esi
    call    process_node
    add     esp, 4
    mov     esi, [esi+4]
    jmp     short next
done:
    pop     esi
    retn
```

Questions:

- What data structure is being traversed?
- What determines the end of traversal?
- What field at each node is the "next" pointer?

## Challenge problems

### Challenge 1

```asm
j__send:
    jmp     dword ptr ds:__imp__send
```

Explain why this function may appear in cross-references and why spending time
inside it is usually wasted.

### Challenge 2

```asm
sub_401600:
    mov     eax, [esp+4]
    cmp     eax, 5
    ja      short default
    movzx   eax, byte ptr [compact_table+eax]
    jmp     dword ptr [handler_table+eax*4]
default:
    xor     eax, eax
    retn
```

This uses a two-level dispatch: a compact byte table maps case values to
handler indices, then a handler table maps indices to addresses. Why would a
compiler use two tables instead of one?

## Solutions with reasoning

### Exercise 1 solution

ECX is a pointer to an object-like structure. `[ecx]` loads a table pointer,
commonly a vtable. `[eax+0x0C]` is the fourth function slot. The call target is
controlled by the table pointer stored at the object base. An exploit developer
asks whether ECX or `[ecx]` can be corrupted before this call. The snippet pushes
one outgoing argument and then returns without `add esp, 4`, so the indirect
callee must use a callee-cleaned convention for that argument. In real thiscall
code, also check whether ECX is meant to remain the object pointer at the call
site.

Plausible pseudocode:

```c
obj->vtable->slot3(arg);
```

### Exercise 2 solution

The input is subtracted by 0x10 before the range check. `cmp eax, 4; ja` limits
the adjusted value to 0-4, meaning the original input handles values 0x10
through 0x14. The subtraction normalizes a sparse range to a zero-based dense
range suitable for a jump table. For input 0x12: `0x12 - 0x10 = 2`, so the
third entry in `table_402100` is used. Looking at the code layout, case_10
handles index 0 (input 0x10) and case_11 handles index 1 (input 0x11). Index 2
(input 0x12) would be a third table entry not shown in the snippet.

### Exercise 3 solution

This is a singly-linked list traversal. The "next" pointer is at offset `+4` in
each node (`mov esi, [esi+4]`). Traversal ends when a node's next pointer is
NULL (`test esi, esi; jz done`). Each node is passed to `process_node`. The
programmer wrote a simple linked-list walker. An exploit developer asks whether
an attacker can corrupt a node's next pointer to redirect traversal to a
controlled memory region.

### Challenge 1 solution

This is an import thunk. It exists so local code can branch to a stable stub
that jumps through the Import Address Table entry for `send`. It contributes API
boundary information, not domain logic. The important question is who calls
`send`, with which socket, buffer pointer, length, and flags.

### Challenge 2 solution

A two-level dispatch handles sparse case values efficiently. If a switch has
cases 0, 1, 5 that all go to handler A and cases 2, 3, 4 that go to handler B,
a single jump table needs 6 entries (one per case value), each pointing to the
correct handler. The two-level approach uses 6 bytes in the compact table
(mapping case -> handler index) plus only 2 dwords in the handler table. For
switches with many case values that map to few unique handlers, this saves
space. The compact table also enables range validation with a single `cmp/ja`
before a byte-sized lookup, which is cheaper than a sparse compare chain.

## Key takeaways

- Switches lower into compare chains (sparse cases) or jump tables (dense
  cases). The range check before a jump table (`cmp/ja`) is the safety gate
  that prevents out-of-bounds table reads.

- Subtraction before a range check normalizes a non-zero-based range for
  jump table indexing. Reverse the subtraction to recover the original case
  values.

- Tail calls (`jmp target` at function end) transfer control without adding
  a stack frame. The callee returns directly to the original caller.

- Import thunks (`jmp [IAT_entry]`) are API boundary markers. Do not analyze
  the thunk itself -- follow callers to find argument setup.

- Indirect calls through object pointers (`call [reg+offset]`) are
  exploit-relevant because corrupting the object or its vtable controls the
  call target.

- Linked list traversal (`mov reg, [reg]` or `mov reg, [reg+offset]`) is
  common in Windows internals. The same pattern appears in PEB walking.

## See also

- `x86-osed-assembly-reference/10-branches-and-control-flow.md` -- switch
  lowering, jump tables, indirect branches
- `x86-osed-assembly-reference/13-call-indirect-and-control-flow-hijacking.md` --
  indirect call exploitation
- `osed-reversing-guide/06-dispatch-and-switches.md` -- command dispatcher
  reversing
- `DRILLS/function_analysis.md` -- dispatch analysis practice

---
