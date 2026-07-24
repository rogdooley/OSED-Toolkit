# Switches, Jump Tables, Tail Calls, and Thunks

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

## Exercises

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

## Challenge problems

```asm
j__send:
    jmp     dword ptr ds:__imp__send
```

Explain why this function may appear in cross-references and why spending time
inside it is usually wasted.

## Solutions with reasoning

Exercise solution:

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

Challenge solution:

This is an import thunk. It exists so local code can branch to a stable stub
that jumps through the Import Address Table entry for `send`. It contributes API
boundary information, not domain logic. The important question is who calls
`send`, with which socket, buffer pointer, length, and flags.

---
