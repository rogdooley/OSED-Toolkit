# 9. MSVC Idioms and Runtime Artifacts

## Learning objectives

- Recognize common MSVC-generated and CRT-like idioms.
- Distinguish programmer logic from compiler-inserted protections.
- Identify copies, clears, string routines, stack cookies, stack probing, SEH,
  function pointers, virtual dispatch, and import thunks.
- Explain why the compiler generated each pattern.
- Understand SEH exploitation mechanics: nSEH/SEH overwrite, POP-POP-RET.
- Know which functions receive /GS stack cookies and which do not.
- Explain why SEH overwrites bypass stack cookies.

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

## /GS stack cookie details

Not every function gets a cookie. MSVC applies /GS protection selectively:

**Functions that DO receive cookies:**

- Functions with stack-allocated buffers larger than 4 bytes (arrays, structs
  with arrays).
- Functions that use `_alloca`.
- Functions with `__except` blocks (SEH filter expressions on the stack).
- Functions whose address is taken and used as a callback.

**Functions that do NOT receive cookies:**

- Leaf functions (no calls to other functions).
- Functions with only scalar locals (int, pointer, no arrays).
- Functions with buffers of 4 bytes or fewer.
- Functions compiled without /GS (rare in modern builds, but check older code).
- Functions marked with `__declspec(safebuffers)`.

### Cookie placement in the frame

```text
+------------------+
| arguments        |
+------------------+
| return address   |
+------------------+
| saved EBP        |  <-- ebp points here
+------------------+
| GS cookie        |  [ebp-4]   -- checked before RET
+------------------+
| local variables  |
| (scalars first)  |
+------------------+
| local buffers    |  <-- overflow starts here, grows upward
+------------------+
| (SEH records,    |
|  if registered)  |  <-- below the buffer, closer to ESP
+------------------+
```

MSVC reorders locals to place buffers at the bottom of the frame (closest to
ESP, farthest from the cookie and return address). This means an upward overflow
must corrupt the cookie before reaching the return address -- the cookie detects
the corruption at function return.

But SEH exception registration records sit below the cookie. This is the key
to SEH-based exploitation.

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

## SEH exploitation mechanics

SEH is the primary OSED technique for bypassing /GS stack cookies. Understanding
the stack layout and the overwrite mechanics is essential.

### The EXCEPTION_REGISTRATION_RECORD

Each x86 SEH registration pushes an 8-byte record onto the stack:

```c
typedef struct _EXCEPTION_REGISTRATION_RECORD {
    struct _EXCEPTION_REGISTRATION_RECORD *Next;  // +0x00: pointer to previous record
    PEXCEPTION_ROUTINE Handler;                    // +0x04: pointer to handler function
} EXCEPTION_REGISTRATION_RECORD;
```

Registration in assembly:

```asm
push    offset handler          ; Handler function address
push    dword ptr fs:[0]        ; Previous record (head of chain)
mov     dword ptr fs:[0], esp   ; New record becomes head of chain
```

### The SEH overwrite layout

When a function has both a /GS cookie and an SEH registration, the stack looks
like this:

```text
High addresses (toward arguments)
+---------------------------+
| arguments                 |
+---------------------------+
| return address            |
+---------------------------+
| saved EBP                 |
+---------------------------+
| GS cookie       [ebp-4]  |  <-- checked at RET (never reached)
+---------------------------+
| local scalars             |
+---------------------------+
| local buffer    [ebp-N]  |  <-- overflow starts here
|    ...                    |
|    ...                    |
+---------------------------+
| nSEH (Next ptr) [esp+4]  |  <-- overwrite with short jmp (EB 06 90 90)
+---------------------------+
| SEH handler    [esp]      |  <-- overwrite with POP-POP-RET address
+---------------------------+
Low addresses (toward ESP)
```

The overflow path, reading upward from the buffer:

1. Attacker fills the local buffer with controlled data.
2. The overflow continues past the buffer boundary.
3. It overwrites `nSEH` (the Next pointer) with a short jump: `EB 06 90 90`.
4. It overwrites the `SEH handler` with the address of a POP-POP-RET gadget.
5. The overflow eventually corrupts the GS cookie -- but this does not matter yet.
6. Before the function returns (and before `__security_check_cookie` runs), the
   overflow triggers an access violation (e.g., writing past the committed stack
   page).
7. Windows dispatches the exception through the SEH chain.
8. The corrupted handler (POP-POP-RET address) executes.
9. POP-POP-RET pops two dwords and returns, landing execution at the `nSEH` field.
10. The short jump at `nSEH` jumps forward into the attacker's shellcode.

### Why POP-POP-RET works

When Windows calls the SEH handler, the stack contains:

```text
ESP+00:  ptr to EXCEPTION_RECORD
ESP+04:  ptr to EXCEPTION_REGISTRATION_RECORD (the nSEH/handler pair on the stack)
ESP+08:  ptr to CONTEXT
ESP+0C:  DispatcherContext
```

The address at ESP+04 points to the `nSEH` field. POP-POP-RET does:

```asm
pop     reg1        ; removes ESP+00 (EXCEPTION_RECORD ptr)
pop     reg2        ; removes ESP+04 -- but the VALUE was the address of nSEH
ret                 ; pops ESP+08... wait -- this needs clarification:
```

Actually, the POP-POP-RET sequence works because after the two POPs, ESP points
to what was at ESP+08, and RET pops that into EIP. But the critical detail is
that the EstablisherFrame (ESP+04 parameter) points back to the
EXCEPTION_REGISTRATION_RECORD on the stack -- i.e., to the nSEH field. The
handler is called with this as a parameter, and when the EXCEPTION_DISPOSITION
return path processes, the POP-POP-RET redirects execution flow through the
corrupted nSEH on the stack. The net effect: execution lands at the nSEH address
on the stack, where the short jump (`EB 06`) skips the 4-byte SEH handler field
and lands in attacker-controlled data (the overflow payload).

### Worked SEH exploit scenario

Consider this function:

```asm
vuln_func:
    push    ebp
    mov     ebp, esp
    sub     esp, 218h
    mov     eax, ___security_cookie
    xor     eax, ebp
    mov     [ebp-4], eax

    ; SEH registration
    push    offset safe_handler
    push    dword ptr fs:[0]
    mov     dword ptr fs:[0], esp

    ; Vulnerable copy
    push    [ebp+0Ch]           ; attacker-controlled length
    push    [ebp+8]             ; attacker-controlled source
    lea     eax, [ebp-200h]    ; 512-byte local buffer
    push    eax
    call    _memcpy
    add     esp, 0Ch

    ; SEH teardown
    mov     ecx, [esp]
    mov     dword ptr fs:[0], ecx
    add     esp, 8

    ; Cookie check
    mov     ecx, [ebp-4]
    xor     ecx, ebp
    call    @__security_check_cookie@4
    mov     esp, ebp
    pop     ebp
    retn
```

**Before overflow** -- `!exchain` output:

```text
0:000> !exchain
0012FA00: vuln_module!safe_handler
0012FFB0: ntdll!_except_handler4+0 (7C91E252)
```

**After overflow with 600 bytes of 'A' (0x41)**:

```text
0:000> !exchain
0012FA00: 41414141
Invalid exception stack at 41414141
```

The handler has been overwritten. In a real exploit, the handler would be
replaced with a POP-POP-RET gadget address, and the nSEH with `EB 06 90 90`.

### Verify in WinDbg

Key commands for SEH analysis:

```text
0:000> !exchain                          ; show exception handler chain
0:000> dt ntdll!_EXCEPTION_REGISTRATION_RECORD <addr>  ; examine record
0:000> !teb                              ; find TEB, FS:[0] is first field
0:000> dd fs:[0] L1                      ; head of SEH chain
0:000> dd poi(fs:[0]) L2                 ; Next and Handler of first record
0:000> u poi(poi(fs:[0])+4)              ; disassemble the handler
```

## SafeSEH and SEHOP

### SafeSEH

SafeSEH is a linker-time mitigation. When enabled, the PE header contains a
table of valid exception handler addresses. At exception dispatch time, the OS
verifies that the handler address appears in the table before calling it.

**Checking SafeSEH status:**

```text
; In WinDbg with narly or checksec:
0:000> !checksec -m vuln_module
    vuln_module
        SafeSEH : TRUE         ; handlers are validated
        ASLR    : FALSE
        DEP     : TRUE

; Or check the DllCharacteristics in the PE header:
0:000> !dh vuln_module -f
    ...
    DLL Characteristics: 0040  ; IMAGE_DLLCHARACTERISTICS_NO_SEH not set
    ...
    Load Config: <addr>
        Size: 0x48
        SEHandlerTable: <addr>  ; present = SafeSEH enabled
        SEHandlerCount: 0x0F
```

**Exploitation strategy with SafeSEH:**

- Find a loaded module that was compiled WITHOUT SafeSEH.
- Use a POP-POP-RET gadget from that module as the SEH handler address.
- Modules compiled without SafeSEH have no handler table, so the OS cannot
  validate the handler and allows the call.
- Common candidates: older third-party DLLs, application-specific modules,
  modules compiled with older toolchains.

### SEHOP (SEH Overwrite Protection)

SEHOP validates the SEH chain integrity at exception time. It checks that the
chain terminates at a known sentinel record. If an overflow breaks the chain
(corrupts the Next pointer), SEHOP detects it.

- Enabled by default on Windows Server 2008+ and Windows 10+.
- Can be disabled per-application via registry for testing.
- SEHOP makes the `nSEH` overwrite unreliable because the corrupted Next pointer
  breaks chain validation.
- OSED exam targets typically have SEHOP disabled.

## Cookie bypass via SEH: worked example

Here is the complete reasoning for why SEH overwrites bypass /GS:

1. The /GS cookie sits between the local buffer and the saved return address.
   It is checked in the function epilogue, right before `ret`.

2. The SEH registration record sits at a lower stack address (closer to ESP)
   than the cookie. In many MSVC-compiled functions, the SEH record is between
   the local buffer and the bottom of the frame.

3. An upward overflow from the local buffer hits the SEH record BEFORE it
   reaches the cookie. Both get corrupted, but the overflow itself may trigger
   an exception (e.g., by writing past the committed stack guard page) before
   the function reaches its epilogue.

4. When the exception fires, Windows walks the SEH chain. It finds the corrupted
   handler address and calls it. The cookie check never executes because the
   function never reaches its `ret` instruction.

5. The corrupted handler (POP-POP-RET) redirects execution to the nSEH field on
   the stack, where the attacker has placed a short jump into the payload.

This is why the SEH overwrite is the primary /GS bypass in OSED: the exception
is triggered and handled before the cookie is checked.

## Common mistakes

- Treating `__security_check_cookie` as an application validation function.
- Calling every `rep movs` safe or unsafe without count/destination analysis.
- Ignoring stack probing and misreading it as an application loop.
- Assuming import thunks are meaningful functions.
- Thinking /GS cookies protect against all stack-based exploits.
- Forgetting that SEH records are stored on the stack, within reach of overflows.

## Exercises

### Exercise 1: Stack probing

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

### Exercise 2: SEH registration with cookie

```asm
sub_401900:
    push    ebp
    mov     ebp, esp
    sub     esp, 210h
    mov     eax, ___security_cookie
    xor     eax, ebp
    mov     [ebp-4], eax

    push    offset __except_handler4
    push    dword ptr fs:[0]
    mov     dword ptr fs:[0], esp

    lea     eax, [ebp-204h]
    push    200h
    push    [ebp+8]
    push    eax
    call    _memcpy
    add     esp, 0Ch

    ; ... more code ...
    mov     ecx, [ebp-4]
    xor     ecx, ebp
    call    @__security_check_cookie@4
    mov     esp, ebp
    pop     ebp
    retn
```

Questions:

- What is the size of the local buffer?
- Is the memcpy safe or unsafe? What determines this?
- If this function were exploitable, which protection (cookie or SEH) could be
  bypassed, and why?
- Draw the stack layout showing the relative positions of the buffer, SEH record,
  cookie, and return address.

### Exercise 3: Identifying /GS candidates

For each function description below, predict whether MSVC would insert a /GS
cookie:

1. Function with a 200-byte local char array and two function calls.
2. Function with only two `int` locals and one function call.
3. Leaf function (no calls) with a 500-byte local buffer.
4. Function using `_alloca(user_len)` with no other buffers.
5. Function with a 2-byte local `short` array and three function calls.

## Challenge problems

### Challenge 1: SEH teardown

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

### Challenge 2: Complete exploit path analysis

```asm
vuln_process:
    push    ebp
    mov     ebp, esp
    sub     esp, 120h
    mov     eax, ___security_cookie
    xor     eax, ebp
    mov     [ebp-4], eax

    push    offset handler_func
    push    dword ptr fs:[0]
    mov     dword ptr fs:[0], esp

    push    0
    push    400h                  ; read up to 1024 bytes
    lea     eax, [ebp-100h]      ; 256-byte local buffer
    push    eax
    push    [ebp+8]              ; socket
    call    _recv
    add     esp, 10h
    ; ... continues ...
```

Map out the full exploit chain: where does the overflow happen, what gets
corrupted in what order, which mitigation is bypassed, and what exploit technique
applies.

## Solutions with reasoning

### Exercise 1 solution

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

### Exercise 2 solution

The local buffer is 0x200 (512) bytes, based on `lea eax, [ebp-204h]` (the
extra 4 bytes at the top are the cookie). The memcpy copies a fixed 0x200 bytes.
Whether this is safe depends on what `[ebp+8]` points to and whether the source
data is attacker-controlled. The copy count is hardcoded and matches the buffer
size, so the memcpy itself does not overflow.

However, if any other code path writes to this buffer without a proper bounds
check, the SEH record below the buffer is the target. The cookie check happens
at function return, but the SEH handler is invoked at exception time -- before
return. So the SEH handler can be corrupted and triggered before the cookie
check ever runs.

Stack layout:

```text
+-------------------+
| arguments         |
+-------------------+
| return address    |
+-------------------+
| saved EBP         |
+-------------------+
| GS cookie [ebp-4] |
+-------------------+
| (other locals)    |
+-------------------+
| buffer[511]       |  ebp-05h
|   ...             |
| buffer[0]         |  ebp-204h
+-------------------+
| SEH next (nSEH)   |
+-------------------+
| SEH handler        |
+-------------------+
```

### Exercise 3 solution

1. YES -- has a buffer > 4 bytes and makes calls.
2. NO -- only scalar locals (int), no arrays.
3. It depends. MSVC historically does not cookie-protect leaf functions even with
   large buffers because there is no `ret` to hijack after a call. However,
   modern MSVC versions may still insert one. In practice, check the binary.
4. YES -- `_alloca` always triggers /GS.
5. NO -- a 2-byte buffer (one `short` element) is <= 4 bytes.

### Challenge 1 solution

This is x86 Structured Exception Handling registration. The function links an
exception registration record through `FS:[0]`, then restores the previous head.
For exploit analysis, SEH matters because stack corruption may overwrite handler
records, and exception paths can transfer control before normal epilogue/cookie
logic depending on layout and compiler options.

### Challenge 2 solution

The overflow path:

1. `recv` reads up to 0x400 (1024) bytes into a buffer at `[ebp-100h]` that is
   only 0x100 (256) bytes.
2. The overflow writes upward through the stack:
   - First corrupts any local variables above the buffer.
   - Then corrupts the GS cookie at `[ebp-4]`.
   - Then corrupts saved EBP and the return address.
3. But the SEH record is below the buffer (closer to ESP). Wait -- actually, in
   this function the SEH record was pushed AFTER `sub esp, 120h`, so it is at
   a lower address than the buffer. The buffer is at `[ebp-100h]` and the SEH
   record is at `[esp]` (which is below `[ebp-120h]`). So the overflow goes
   UPWARD from the buffer, past locals, past the cookie, toward the return
   address.

   The SEH is below the buffer in this layout, so the upward overflow does NOT
   hit the SEH record. The cookie WILL catch this overflow.

   Corrected analysis: to exploit this via SEH, you would need the overflow to
   go downward, or the SEH record would need to be at a higher address. In this
   case, the primary exploit path is to leak the cookie or find a write-what-where
   before the cookie check.

   This is an important lesson: always draw the actual stack layout before
   assuming the SEH bypass applies. The relative positions of buffer, SEH record,
   and cookie determine the exploit strategy.

## Key takeaways

- MSVC inserts /GS cookies only in functions with stack buffers > 4 bytes,
  `_alloca`, or `__except` blocks. Leaf functions and scalar-only functions
  typically get no cookie.
- SEH overwrites bypass /GS because the exception handler is invoked before the
  function returns and before the cookie is checked.
- The SEH exploit pattern is: overflow buffer -> overwrite nSEH with short jmp
  -> overwrite handler with POP-POP-RET -> trigger exception -> gain execution.
- SafeSEH validates handler addresses against a PE table. Bypass it by using
  gadgets from non-SafeSEH modules.
- Always draw the stack layout. The relative positions of buffer, SEH record,
  and cookie determine whether the SEH bypass applies.

## See also

- `x86-osed-assembly-reference/` chapters 07 (stack fundamentals), 08 (function
  stack frames), 11 (buffers and stack overflows), 15 (DEP and page protections)
- `osed-reversing-guide/` chapters 03 (stack and frames), 09 (library idioms),
  12 (IDA-WinDbg loop)
- `DRILLS/stack_overflow.md` -- SEH overwrite practice scenarios
- `DRILLS/primitive_identification.md` -- identifying exploit primitives

---
