# Chapter 4 — Calling Conventions, Prologues, Epilogues, Arguments, and Locals

## 1. Objective

After this chapter you can identify a function's **calling convention**
(`__cdecl`, `__stdcall`, `__fastcall`, `__thiscall`) from its call sites and
cleanup, recover its **argument count and passing order**, distinguish arguments
from locals reliably, and recognize the prologue/epilogue variants MSVC emits.
This lets you write a correct C prototype for an unknown function.

## 2. Background

A calling convention is a contract between caller and callee about *how arguments
are passed, who cleans them up, and which registers survive the call*. The
compiler picks one per function (often dictated by the API being implemented) and
follows it exactly. Because it's a contract, both sides encode evidence of it: the
caller shows how it passes and cleans args; the callee shows how it receives them
and whether it cleans on return. You cross-check the two.

Why it matters for reversing: the convention tells you **how many arguments** a
function takes and **where to read them** (stack vs `ECX`/`EDX`), which is exactly
what you need to reconstruct a signature and to understand data flow into the
function.

## 3. Mental model

Four conventions dominate 32-bit Windows. Keep this comparison as your reference:

```
   Convention   Args passed          Who cleans stack   Name decoration (MSVC)
   ----------   -----------------    ----------------   ----------------------
   __cdecl      all on stack, R->L   CALLER (add esp)   _func
   __stdcall    all on stack, R->L   CALLEE (retn N)    _func@N   (N = arg bytes)
   __fastcall   ECX, EDX, then stack CALLEE (retn N)    @func@N
   __thiscall   ECX = this, rest     CALLEE (usually)   (C++ member funcs)
                stack R->L
```

The two questions that decide everything:

1. **Where do the pushes stop and the register loads begin?** All args pushed →
   cdecl/stdcall. First one or two args loaded into `ECX`/`EDX` before the call →
   fastcall/thiscall.
2. **Who removes the arguments after the call?** `add esp, N` in the *caller*
   right after the `call` → caller cleanup → `__cdecl`. `retn N` in the *callee* →
   callee cleanup → `__stdcall`/`__fastcall`.

`__cdecl` is the only one where the caller cleans, which is *why* it's the one that
supports varargs (`printf`): only the caller knows how many arguments it actually
passed. Seeing caller cleanup + variable arg counts across call sites = a varargs
cdecl function. That's a derivation, not a lookup.

## 4. Assembly examples

```asm
; __cdecl: caller pushes and caller cleans
    push    3                   ; arg3
    push    2                   ; arg2
    push    1                   ; arg1  (right-to-left, so arg1 ends up lowest)
    call    _add3
    add     esp, 0Ch            ; CALLER frees 3*4 bytes  -> __cdecl

_add3:
    push    ebp
    mov     ebp, esp
    mov     eax, [ebp+8]        ; arg1
    add     eax, [ebp+0Ch]      ; + arg2
    add     eax, [ebp+10h]      ; + arg3
    pop     ebp
    retn                        ; bare retn (no N) -> caller will clean -> cdecl
```

```asm
; __stdcall: caller pushes, CALLEE cleans (retn N)
    push    eax
    push    ecx
    call    _MyApi@8
    ; (no add esp here) -> callee cleaned

_MyApi@8:
    push    ebp
    mov     ebp, esp
    ...
    pop     ebp
    retn    8                   ; callee frees 8 bytes -> 2 dword args -> __stdcall
```

`retn 8` is decisive: the callee pops the return address *and* discards 8 bytes of
arguments in one instruction. `8 / 4 = 2` stack arguments. Nearly all Win32 API
functions are `__stdcall`; the `@8` decoration and `retn 8` corroborate.

```asm
; __fastcall / __thiscall: first args in registers
    mov     edx, esi            ; arg2 -> EDX
    mov     ecx, [ebp+8]        ; arg1 (or 'this') -> ECX
    call    sub_401300
    ; ...

sub_401300:
    ; body reads ECX and EDX directly as its first two args;
    ; additional args (if any) come from [esp+4], [esp+8], ...
    retn    4                   ; cleans the ONE stacked extra arg (3rd arg)
```

When the two instructions immediately before a `call` load `ECX` (and maybe
`EDX`), the first arguments are register-passed. If it's *only* `ECX` and the
function is a C++ method (you'll see it dereference `ECX` as an object), it's
`__thiscall` and `ECX` is `this`.

## 5. Equivalent C

```c
int  __cdecl   add3(int a, int b, int c);      // push*3 + add esp,0xC + bare retn
int  __stdcall MyApi(int a, int b);            // push*2, no caller cleanup, retn 8
int  __fastcall f(int a /*ECX*/, int b /*EDX*/, int c /*stack*/);  // retn 4

// __thiscall (C++)
class C { int method(int x); };                // ECX = this, x on stack
```

## 6. Reverse engineering methodology

To recover a signature:

1. **Go to a call site.** Count the `push`es that set up arguments (watch for
   `push` used for other reasons — but immediately-before-`call` pushes are
   almost always args).
2. **Check for register loads of ECX/EDX** right before the `call`. If present,
   add those as the first one/two args (fastcall/thiscall).
3. **Determine cleanup.** `add esp, N` after the call → caller cleans → `__cdecl`.
   Nothing after, and `retn N` in the callee → callee cleans → `__stdcall`/
   `__fastcall`.
4. **Count args** = (bytes cleaned / 4) + (register args). Cross-check caller
   pushes vs callee's `retn N`.
5. **Infer arg types** from *use inside the callee* (Chapters 1–2): dereferenced →
   pointer; `*4` indexed → array/int; `movsx` → signed small int; passed straight
   to a known API → that API's type.
6. **Name and prototype** the function in IDA (`Y` to set type) so the decompiler
   and xrefs propagate it.

Multiple call sites are your friend: if three callers each `add esp, 8`, you've
triangulated a 2-arg cdecl function even without reading the body.

## 7. Common compiler idioms

- **`retn N`** = callee cleanup; `N/4` = stack arg count.
- **`add esp, N` right after `call`** = caller cleanup (cdecl). Sometimes the
  compiler *reuses* the popped space and you'll see the args re-pushed for the
  next call instead of an explicit `add esp` — treat a matching later adjustment
  the same way.
- **`mov ecx, <obj>` immediately before `call`** in C++ code = `this` pointer =
  `__thiscall`.
- **Register args via ECX/EDX** = `__fastcall`; look for the two `mov`s just
  before the call.
- **Prologue variants:** `leave` for the epilogue; `_alloca_probe` (`call
  __chkstk`) when locals exceed a page (0x1000) — MSVC probes the stack to grow it
  safely, so a `call __chkstk` after `mov eax, <bigsize>` means "large local
  frame," not a real function call.
- **Naked/optimized functions** may skip the standard prologue entirely; fall back
  to ESP-relative reading (Chapter 11).

## 8. Common mistakes

- **Counting every `push` as an argument.** Register saves (`push esi`, `push edi`,
  `push ebx`) at the top of a body are callee-saved-register preservation, not
  arguments. Arguments are the pushes *at the call site* just before `call`.
- **Missing register-passed args.** A fastcall function looks like it takes fewer
  stack args than it really uses; you'll under-count if you ignore the `ECX`/`EDX`
  loads.
- **Assuming `retn` with no operand means zero args.** It means *caller* cleanup
  (cdecl); the args are still there, cleaned by the caller's `add esp, N`.
- **Trusting IDA's guessed prototype blindly.** IDA infers conventions well but not
  perfectly, especially with FPO or custom conventions. Verify cleanup yourself.
- **Ignoring callee-saved restores at the epilogue** (`pop edi / pop esi / pop
  ebx`) and miscounting the frame. Those balance the pushes at the top, they're
  not returns of data.

## 9. Exercises

1. A callee ends with `retn 10h`. Its callers pass some args in registers: you see
   `mov ecx, X` and `mov edx, Y` before each `call`. How many *total* arguments,
   and what convention?
2. Three different call sites for the same target each do exactly two pushes and
   then `add esp, 8`. What convention, how many args, and can you tell the types
   without reading the body?
3. Why does `__cdecl` support `printf`-style varargs while `__stdcall` cannot?
   Derive the reason from who cleans the stack.
4. You see `push esi / push edi` at the very start of a function body and `pop edi
   / pop esi` at the end. Are these arguments? What are they?

## 10. Summary

- A calling convention is a caller/callee contract about argument passing, cleanup,
  and register preservation; the compiler follows one consistently, leaving
  evidence on both sides.
- **Who cleans the stack** is the key discriminator: caller (`add esp,N`) →
  `__cdecl`; callee (`retn N`) → `__stdcall`/`__fastcall`.
- **Register-loaded ECX/EDX before a call** → `__fastcall`; ECX-as-`this` → C++
  `__thiscall`.
- Argument count = bytes cleaned / 4 + register args; cross-check caller pushes
  against the callee's `retn N`.
- Recover types from *how the callee uses* each argument, then set the prototype in
  IDA so it propagates.
