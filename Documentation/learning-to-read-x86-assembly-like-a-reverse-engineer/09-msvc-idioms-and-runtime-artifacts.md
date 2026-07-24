# MSVC Idioms and Runtime Artifacts

## Learning objectives

- Recognize common MSVC-generated and CRT-like idioms.
- Distinguish programmer logic from compiler-inserted protections.
- Identify copies, clears, string routines, stack cookies, stack probing, SEH,
  function pointers, virtual dispatch, and import thunks.
- Explain why the compiler generated each pattern.

## Concept discussion

Compiler idioms are shortcuts, not conclusions. You should recognize them, then
prove the contract:

- Copy: destination, source, count, overlap behavior.
- Clear: destination, value, count.
- String operation: terminator, maximum length, output termination.
- Cookie: saved cookie, check before return, failure target.
- Stack probing: page touching for large local allocation.
- SEH: exception registration manipulation via FS:[0].
- Virtual/function pointer call: data controls code address.
- Import thunk: API boundary.

MSVC emits these patterns because it must implement ABI rules, security options,
runtime checks, and optimized library behavior.

## Common compiler patterns

- `rep stosd/stosb`: memset-like initialization.
- `rep movsd/movsb`: memcpy-like copy.
- `call @__security_check_cookie@4`: stack cookie verification.
- `xor eax, ebp` near prologue: cookie derivation.
- `call __chkstk`: stack probing for large frames.
- `push offset handler; push fs:[0]; mov fs:[0],esp`: x86 SEH registration.
- `jmp dword ptr ds:__imp__API`: import thunk.

## Fully annotated example

```asm
sub_401800:
    push    ebp
    mov     ebp, esp
    sub     esp, 84h
    mov     eax, ___security_cookie
    xor     eax, ebp
    mov     [ebp-4], eax
    lea     edi, [ebp-84h]
    xor     eax, eax
    mov     ecx, 20h
    rep     stosd
    lea     eax, [ebp-84h]
    push    eax
    call    sub_402100
    add     esp, 4
    mov     ecx, [ebp-4]
    xor     ecx, ebp
    call    @__security_check_cookie@4
    mov     esp, ebp
    pop     ebp
    retn
```

Annotated:

```asm
mov eax, ___security_cookie / xor eax, ebp / mov [ebp-4], eax
; Stack cookie stored in the frame. This is compiler-inserted protection, not
; programmer business logic.

lea edi, [ebp-84h] / xor eax,eax / mov ecx,20h / rep stosd
; Clear 0x20 dwords = 0x80 bytes of local buffer/object.

call sub_402100
; Programmer logic resumes: pass the cleared local object to another function.

mov ecx,[ebp-4] / xor ecx,ebp / call __security_check_cookie
; Verify cookie before returning.
```

The compiler generated the cookie because the function has stack objects that
qualify for protection. The programmer wrote code that needed a local object and
a call using that object.

## Reverse engineering thought process

Mark runtime artifacts in your notes:

```text
compiler: frame, cookie setup/check, rep stosd clear
programmer: zero-initialized local object passed to sub_402100
unknown: what sub_402100 does with that object
```

An exploit developer does not ignore the cookie. They classify it: stack smash
may be detected before RET, so exploit strategy may require one of these bypass
approaches:

- **SEH overwrite**: if the function registers an SEH handler and the buffer
  overflow reaches the exception registration record, triggering an exception
  before the cookie check transfers control through the corrupted handler.
- **Cookie disclosure**: an information leak in a prior request or response
  reveals the cookie value, allowing the attacker to reconstruct the expected
  cookie in the overflow payload.
- **Write-what-where**: if the overflow corrupts a pointer or index used in a
  write before the function returns, the attacker gains an arbitrary write
  without needing to pass the cookie check.
- **Non-cookie-covered path**: the compiler does not protect every function.
  A different call site or a function without `/GS` protection may offer the
  same overflow without a cookie.
- **Heap or global corruption**: the vulnerable copy writes past the stack
  frame into adjacent memory, but the exploit targets heap metadata, a global
  function pointer, or a vtable rather than the saved return address.

## Common mistakes

- Treating `__security_check_cookie` as an application validation function.
- Calling every `rep movs` safe or unsafe without count/destination analysis.
- Ignoring stack probing and misreading it as an application loop.
- Assuming import thunks are meaningful functions.

## Exercises

```asm
sub_401870:
    push    ebp
    mov     ebp, esp
    mov     eax, 5000h
    call    __chkstk
    lea     eax, [ebp-5000h]
    push    eax
    call    sub_402300
    add     esp, 4
    mov     esp, ebp
    pop     ebp
    retn
```

Questions:

- Why does `__chkstk` exist?
- What programmer-level fact caused this pattern?
- What should you analyze next?

## Challenge problems

```asm
    push    offset handler
    push    dword ptr fs:[0]
    mov     dword ptr fs:[0], esp
    ...
    mov     ecx, [esp]
    mov     dword ptr fs:[0], ecx
    add     esp, 8
```

Identify the pattern and explain how it affects exploit-oriented analysis.

## Solutions with reasoning

Exercise solution:

On 32-bit MSVC, `__chkstk` is the compiler helper used for large stack
allocations. The requested allocation size is placed in EAX, and the helper
probes the guard pages while establishing the large stack frame. Do not add a
second `sub esp, eax` after this pattern unless you have verified the exact
helper convention in the target compiler/runtime. The programmer-level fact is a
large local object or alloca-like allocation around `0x5000` bytes. A real build with this allocation size would likely also include a stack cookie;
it is omitted here to focus on the probing pattern. Analyze `sub_402300` and all
writes to the large local buffer; the probe itself is not domain logic.

Plausible pseudocode:

```c
void f(void) {
    unsigned char big[0x5000];
    sub_402300(big);
}
```

Challenge solution:

This is x86 Structured Exception Handling registration. The function links an
exception registration record through `FS:[0]`, then restores the previous head.
For exploit analysis, SEH matters because stack corruption may overwrite handler
records, and exception paths can transfer control before normal epilogue/cookie
logic depending on layout and compiler options.

---
