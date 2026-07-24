# Frames, Arguments, Locals, CALL, and RET

## Learning objectives

- Recover stack-frame shape and argument count from x86 code.
- Distinguish locals, saved registers, outgoing arguments, and return values.
- Infer likely calling convention from cleanup behavior.
- Recognize when frame code is compiler scaffolding.

## Concept discussion

A function frame is the compiler's workspace. It exists because the programmer
needed locals, calls, preserved registers, or stable stack references. It does
not necessarily mean the programmer consciously used the stack.

The frame answers:

- Where can the compiler keep local state?
- Which registers must survive this function?
- Who removes arguments from the stack after a call?
- Where does the return value appear?

In 32-bit MSVC, a debug or non-optimized function often uses EBP as a stable
frame pointer:

```asm
push ebp
mov  ebp, esp
sub  esp, local_size
...
mov  esp, ebp
pop  ebp
retn
```

Arguments appear above EBP: `[ebp+8]`, `[ebp+0Ch]`, `[ebp+10h]`. Locals appear
below EBP: `[ebp-4]`, `[ebp-20h]`.

## Common compiler patterns

- `push esi` / `pop esi`: callee-saved register preservation.
- `sub esp, 80h`: local stack allocation.
- `lea eax, [ebp-40h]`: address of a local buffer.
- `push [ebp+0Ch]; push [ebp+8]; call target; add esp, 8`: cdecl-style caller cleanup.
- `retn 8`: callee cleanup, common in stdcall.
- `mov eax, imm` before epilogue: return value.

## Fully annotated example

```asm
sub_401100:
    push    ebp
    mov     ebp, esp
    sub     esp, 44h
    push    esi
    mov     esi, [ebp+8]
    lea     eax, [ebp-40h]
    push    40h
    push    esi
    push    eax
    call    _memcpy
    add     esp, 0Ch
    xor     eax, eax
    pop     esi
    mov     esp, ebp
    pop     ebp
    retn
```

Annotated:

```asm
sub esp, 44h
; Reserve 0x44 bytes of local storage. The interesting object later starts at
; ebp-0x40, so four bytes may be padding, a temp, or alignment.

push esi
; Preserve ESI because this function uses it and must restore it.

mov esi, [ebp+8]
; First argument copied into ESI. Later passed as source, so it is probably a
; source pointer.

lea eax, [ebp-40h]
; Compute address of local buffer. LEA does not read from the buffer.

push 40h / push esi / push eax / call _memcpy
; Arguments are pushed right-to-left: memcpy(dst=&local, src=arg0, len=0x40).

add esp, 0Ch
; Caller cleaned three 4-byte arguments.
```

The CPU is answering: "Copy exactly 64 bytes from the caller-supplied pointer into
a local stack buffer, then report success."

## Reverse engineering thought process

First draw the frame:

```text
[ebp+8]    arg0: source pointer
[ebp+4]    return address
[ebp]      saved EBP
[ebp-4]    unknown/padding/temp
[ebp-40h]  local buffer begins
```

Then separate scaffolding from semantics:

- Frame setup/teardown: scaffolding.
- `push esi`/`pop esi`: scaffolding.
- `lea [ebp-40h]`, `push 40h`, `_memcpy`: semantics.

## Common mistakes

- Treating every stack slot as a distinct programmer variable.
- Assuming `sub esp, 44h` means a 68-byte buffer. The used buffer may be smaller.
- Forgetting that pushes before a call are usually outgoing arguments.
- Ignoring whether `retn` has an immediate operand.

## Exercises

Assembly only:

```asm
sub_401160:
    push    ebp
    mov     ebp, esp
    sub     esp, 20h
    lea     eax, [ebp-20h]
    push    eax
    push    [ebp+8]
    call    sub_402000
    add     esp, 8
    mov     esp, ebp
    pop     ebp
    retn
```

Questions:

- How many explicit stack arguments does this function use?
- Which stack object is passed by address?
- Who cleans up the call to `sub_402000`?
- What can you infer about the called function's parameters?

## Challenge problems

```asm
sub_4011A0:
    push    ebp
    mov     ebp, esp
    push    edi
    mov     edi, [ebp+8]
    push    [ebp+0Ch]
    call    dword ptr [edi+10h]
    pop     edi
    pop     ebp
    retn    8
```

Explain the calling convention of `sub_4011A0` and the nature of the call target.

## Solutions with reasoning

Exercise solution:

The function uses one explicit incoming argument, `[ebp+8]`. It creates a
32-byte local object and passes its address to `sub_402000`, along with the
incoming argument. `add esp,8` means this function cleans the two outgoing
arguments after the call, so the target is being called as cdecl or through a
cdecl-compatible prototype.

Plausible pseudocode:

```c
void wrapper(void *arg) {
    unsigned char local[32];
    sub_402000(arg, local);
}
```

Challenge solution:

`retn 8` means `sub_4011A0` cleans two caller-supplied arguments, consistent with
stdcall or thiscall-like external usage. The call target is loaded from
`[edi+10h]`, where EDI came from the first argument. That is an indirect call
through a structure field or vtable-like slot. Because this function pushes one
outgoing argument before the indirect call and does not execute `add esp, 4`
afterward, the indirect callee must clean that argument, for example by returning
with `retn 4`. If it were cdecl, `pop edi` would consume the stale argument
instead of the saved EDI and the frame would unwind incorrectly. The programmer
likely wrote a callback or method dispatch. An exploit developer asks whether
`[edi+10h]` can be controlled.

---
