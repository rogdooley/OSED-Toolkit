# 2. Frames, Arguments, Locals, CALL, and RET

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
[ebp-1]    local buffer top (last byte of 0x40-byte memcpy destination)
[ebp-40h]  local buffer begins (first byte of memcpy destination)
[ebp-44h]  padding/temp/alignment (4 extra bytes from sub esp, 44h)
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

### ESP-relative frames (optimized builds)

In optimized or release builds, MSVC may omit the EBP frame pointer entirely.
Instead, all local variables and arguments are accessed relative to ESP. This
is called Frame Pointer Omission (FPO).

```asm
sub_401200:
    sub     esp, 20h
    mov     eax, [esp+24h]        ; first argument (no saved EBP)
    lea     ecx, [esp]            ; local buffer at ESP
    push    20h
    push    eax
    push    ecx
    call    _memcpy
    add     esp, 0Ch
    add     esp, 20h
    retn
```

In FPO frames, every `push` changes the meaning of all `[esp+X]` references
that follow it. The argument at `[esp+24h]` is `[esp + 0x20 (local alloc) +
0x04 (return address)]`. After the three pushes for memcpy, the same argument
would be at `[esp+30h]`.

IDA usually tracks ESP adjustments and labels arguments correctly, but in raw
disassembly you must count every push and sub to know what each `[esp+X]`
references. This is one reason EBP-based frames are easier to reverse: EBP is
stable throughout the function.

## Exercises

### Exercise 1

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

### Exercise 2

```asm
sub_4011C0:
    push    ebp
    mov     ebp, esp
    sub     esp, 10h
    push    esi
    push    edi
    mov     esi, [ebp+8]
    mov     edi, [ebp+0Ch]
    mov     ecx, [ebp+10h]
    lea     eax, [ebp-10h]
    push    ecx
    push    esi
    push    eax
    call    _memcpy
    add     esp, 0Ch
    lea     eax, [ebp-10h]
    push    [ebp+10h]
    push    eax
    push    edi
    call    _memcpy
    add     esp, 0Ch
    pop     edi
    pop     esi
    mov     esp, ebp
    pop     ebp
    retn
```

Questions:

- How many arguments does this function take?
- What does the function do with the local buffer?
- Draw the frame layout showing arguments, locals, and saved registers.
- What is the security risk?

### Exercise 3

```asm
sub_4011E0:
    sub     esp, 40h
    mov     eax, [esp+44h]
    push    eax
    call    sub_403000
    add     esp, 4
    test    eax, eax
    jz      short fail
    mov     [esp+3Ch], eax
    lea     ecx, [esp]
    push    40h
    push    ecx
    push    eax
    call    sub_403100
    add     esp, 0Ch
    xor     eax, eax
    add     esp, 40h
    retn
fail:
    mov     eax, 0FFFFFFFFh
    add     esp, 40h
    retn
```

Questions:

- Is this an EBP frame or an ESP-relative frame?
- Where is the first argument accessed?
- After the first call returns and the result is stored at `[esp+3Ch]`, what
  stack slot is that relative to the function's frame?

## Challenge problems

### Challenge 1

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

### Challenge 2

```asm
sub_401220:
    push    ebp
    mov     ebp, esp
    sub     esp, 8
    push    esi
    mov     esi, [ebp+8]
    lea     eax, [ebp-8]
    push    eax
    push    esi
    call    sub_405000
    add     esp, 8
    cmp     dword ptr [ebp-4], 0
    jz      short done
    push    [ebp-8]
    push    esi
    call    sub_405100
    add     esp, 8
done:
    pop     esi
    mov     esp, ebp
    pop     ebp
    retn
```

How many locals does this function use? What is the relationship between
`[ebp-8]` and `[ebp-4]`? What is the control flow pattern?

## Solutions with reasoning

### Exercise 1 solution

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

### Exercise 2 solution

Three arguments: source pointer (`[ebp+8]`), destination pointer (`[ebp+0Ch]`),
and count (`[ebp+10h]`). The function copies `count` bytes from source into a
16-byte local buffer, then copies from the local buffer into the destination.

Frame layout:

```text
[ebp+10h]  arg2: count
[ebp+0Ch]  arg1: destination pointer
[ebp+08h]  arg0: source pointer
[ebp+04h]  return address
[ebp]      saved EBP
[ebp-04h]  (local buffer bytes 13-16)
[ebp-10h]  local buffer start (16 bytes)
[ebp-14h]  saved EDI (from push edi)
[ebp-18h]  saved ESI (from push esi)
```

Security risk: the local buffer is only 16 bytes (`sub esp, 10h`), but the
count argument is used directly without a bounds check. If count exceeds 16,
the first memcpy overflows the local buffer, corrupting saved ESI, saved EDI,
saved EBP, and the return address.

### Exercise 3 solution

This is an ESP-relative frame (no `push ebp / mov ebp, esp`). The first
argument is at `[esp+44h]` -- that is `esp + 0x40 (local allocation) + 0x04
(return address)`. After `sub_403000` returns, the result is stored at
`[esp+3Ch]`, which is the top 4 bytes of the 64-byte local allocation -- slot
`[frame_base + 0x3C]`, or effectively `local_var_4` if this were an EBP frame.
The function allocates a resource, stores it as a local, then passes it along
with a local buffer and a size to a second function.

### Challenge 1 solution

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

### Challenge 2 solution

The function allocates 8 bytes of local storage, which represents two dword
locals: `[ebp-8]` and `[ebp-4]`. It passes the address of `[ebp-8]` (the
base of the 8-byte block) to `sub_405000` as an output parameter. After that
call, `[ebp-4]` is checked as a boolean flag. If nonzero, `[ebp-8]` is used
as an argument to a second call.

The two locals form a pair -- likely a result structure where `[ebp-4]` is a
status/flag and `[ebp-8]` is a value (pointer, handle, or count). The control
flow pattern is: "query something, then conditionally act on the result."

## Key takeaways

- Stack frames exist because the compiler needs workspace, not because the
  programmer wrote stack operations. Separate frame setup/teardown from
  programmer semantics.

- Arguments live above EBP (`[ebp+8]`, `[ebp+0Ch]`, ...) and locals live below
  EBP (`[ebp-4]`, `[ebp-20h]`, ...). The gap between `sub esp, N` and the
  actual variables used may include padding or alignment.

- ESP-relative frames (FPO) are common in optimized builds. Every push changes
  the meaning of all `[esp+X]` references -- track ESP adjustments carefully.

- `retn N` vs `retn` reveals calling convention: stdcall/thiscall cleans N bytes
  of arguments, cdecl uses bare `retn` and the caller cleans up with
  `add esp, N`.

- An indirect call through a structure field or vtable slot (`call [reg+offset]`)
  means an attacker who controls the object pointer controls the call target.

## See also

- `x86-osed-assembly-reference/07-stack-fundamentals.md` -- stack mechanics,
  push/pop, ESP behavior
- `x86-osed-assembly-reference/08-function-stack-frames.md` -- EBP frames,
  FPO, local variable layout
- `x86-osed-assembly-reference/09-calling-conventions-and-abi.md` -- cdecl,
  stdcall, thiscall, fastcall details
- `osed-reversing-guide/03-stack-and-frames.md` -- practical frame analysis
- `DRILLS/function_analysis.md` -- function analysis drill template

---
