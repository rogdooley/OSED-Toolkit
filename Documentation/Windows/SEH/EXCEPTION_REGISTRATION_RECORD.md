# EXCEPTION_REGISTRATION_RECORD — Structure Reference for Exploit Development

## Purpose

This document covers the `EXCEPTION_REGISTRATION_RECORD` structure at the binary level — its layout, lifecycle on the stack, how compilers generate it, and exactly how it is weaponized during SEH-based stack overflow exploitation. Understanding this structure precisely is required before writing or analyzing SEH exploits, since the entire `POP POP RETN` technique depends on the relationship between the structure's fields and the x86 stack state at handler dispatch time.

---

## Structure Definition

The `EXCEPTION_REGISTRATION_RECORD` is defined in the Windows DDK/WDK headers and in `<excpt.h>`:

```c
typedef struct _EXCEPTION_REGISTRATION_RECORD {
    struct _EXCEPTION_REGISTRATION_RECORD *Next;    // +0x00 (4 bytes)
    PEXCEPTION_ROUTINE                     Handler; // +0x04 (4 bytes)
} EXCEPTION_REGISTRATION_RECORD, *PEXCEPTION_REGISTRATION_RECORD;
```

Total size: **8 bytes** on x86. This is the complete structure as far as the Windows exception dispatcher (`ntdll!RtlDispatchException`) is concerned. The OS reads only these two fields when walking the SEH chain.

### Field Map

```
Offset  Size  Field    Description
──────  ────  ───────  ──────────────────────────────────────────────────
+0x00   4     Next     Pointer to the next EXCEPTION_REGISTRATION_RECORD
                       in the chain, or 0xFFFFFFFF (terminator sentinel)
+0x04   4     Handler  Pointer to the exception handler function
                       Signature: EXCEPTION_DISPOSITION fn(EXCEPTION_RECORD*,
                       void*, CONTEXT*, void*)
```

---

## Why Only 8 Bytes?

The 8-byte layout is intentional minimalism. The OS exception dispatcher only needs two pieces of information to walk the chain:

1. Where is the next record? (`Next`)
2. What function handles exceptions for this frame? (`Handler`)

Higher-level constructs built on top of SEH — such as MSVC's `__try/__except` frames — **extend** this structure with additional compiler-specific fields, but the OS only ever reads the base 8 bytes. Everything else is convention between the compiler and the runtime library.

For example, MSVC's internal `_EXCEPTION_REGISTRATION` used by `__except_handler4` (the handler used in `_except_handler4`-based frames) looks like:

```c
// MSVC internal extended frame (not the OS structure)
struct EH4_EXCEPTION_REGISTRATION {
    EXCEPTION_REGISTRATION_RECORD base;   // +0x00: the OS-visible 8 bytes
    PDISPATCH_CONTEXT              ScopeTable;   // +0x08: compiler scope table
    DWORD                          TryLevel;     // +0x0C: current nesting depth
    DWORD                          _ebp;         // +0x10: saved EBP for frame
};
```

The OS still only reads `base.Next` and `base.Handler`. The `ScopeTable` and `TryLevel` fields are used by the C runtime handler (`__except_handler4`) itself after it is called by the OS.

---

## The `Next` Field in Detail

`Next` holds the address of the **previous** `EXCEPTION_REGISTRATION_RECORD` in the chain — "previous" meaning the one registered before this one, which was already on the stack when this function was entered. Since SEH records are pushed onto the stack as functions with `__try` blocks are entered, the chain runs from the innermost (most recently registered) to the outermost (first registered) frame.

The `Next` field is **not** a pointer to the handler function of the next record. This distinction is critical:

```
Record at 0x0012FF50:
  +0x00  Next    = 0x0012FF70   ← address of the NEXT RECORD (another EXCEPTION_REGISTRATION_RECORD)
  +0x04  Handler = 0x7C91E920   ← address of handler FUNCTION for THIS record
```

When an SEH overflow corrupts a record, the attacker writes:
- `Next` field: typically `\xeb\x06\x90\x90` — a short jump instruction followed by NOPs (details in `SEH_Exploitation.md`)
- `Handler` field: the address of a `POP POP RETN` gadget

The `Next` field becomes code, not a data pointer. Execution lands there after the `POP POP RETN` gadget executes and `RETN` loads the record's address into EIP.

---

## Stack Residency: Why Records Are In the Overflow Path

`EXCEPTION_REGISTRATION_RECORD` structures live **on the thread's stack**. They are not heap-allocated or globally stored. Each function that contains a `__try` block allocates an `EXCEPTION_REGISTRATION_RECORD` (or a larger extended variant) in its stack frame during the prologue.

The stack layout during a typical function with an SEH frame:

```
Higher addresses (older frames)
┌───────────────────────────────────┐
│  Caller's stack frame             │
├───────────────────────────────────┤  ← EBP (saved frame pointer)
│  Saved EBP                        │  +0x00 relative to EBP
├───────────────────────────────────┤
│  Handler address                  │  +0x04 (EXCEPTION_REGISTRATION +0x04)
├───────────────────────────────────┤
│  Old fs:[0] (Next field)          │  +0x08 (EXCEPTION_REGISTRATION +0x00)
├───────────────────────────────────┤  ← address stored in fs:[0]
│  Local variable(s)                │
├───────────────────────────────────┤
│  Overflow buffer (e.g. char[256]) │  ← overflow starts here
└───────────────────────────────────┘
Lower addresses (newer stack data)
```

When the buffer is overflowed upward (toward higher addresses), the bytes fill: the rest of the buffer, any other local variables, any alignment/padding, saved EBP, and then the `EXCEPTION_REGISTRATION_RECORD`. The overflow corrupts `Next` first, then `Handler`.

Note: the exact order depends on the compiler's local variable layout. In many cases, saved EBP appears between the overflow buffer and the SEH record, because the SEH record is placed higher in the frame (it was pushed earlier — onto a less-deep stack — and the buffer was allocated later).

---

## How Compilers Generate SEH Registration

### MSVC Prologue for a `__try` Block

When MSVC compiles a function containing `__try`, it generates a prologue that explicitly registers the SEH frame. Here is what the disassembly typically looks like (simplified, optimizations off):

```asm
; Function prologue with SEH registration
PUSH    EBP                         ; save caller's frame pointer
MOV     EBP, ESP                    ; set up new frame
PUSH    -1                          ; TryLevel = -1 (no active try block yet)
PUSH    OFFSET __except_handler4    ; push handler address onto stack
PUSH    DWORD PTR fs:[00000000h]    ; push current chain head (becomes Next)
MOV     DWORD PTR fs:[00000000h], ESP  ; update fs:[0] to point to our record
SUB     ESP, 0C0h                   ; allocate space for locals + security cookie
PUSH    EBX
PUSH    ESI
PUSH    EDI
MOV     DWORD PTR [EBP-18h], ESP   ; save ESP into frame for unwind
LEA     EAX, DWORD PTR [EBP-10h]
MOV     DWORD PTR fs:[00000000h], EAX ; update fs:[0] to final position
; ... function body ...
```

After this prologue, the stack in the region of the SEH record looks like:

```
[EBP - 0x04]  = handler address (__except_handler4 or similar)
[EBP - 0x08]  = old fs:[0]  (Next pointer)
```

So `fs:[0]` points to `[EBP - 0x08]`, which is the `EXCEPTION_REGISTRATION_RECORD`:
- `[EBP - 0x08]` = `Next` field = old fs:[0]
- `[EBP - 0x04]` = `Handler` field = handler address

### Epilogue: Unlinking the Frame

On normal function exit, the epilogue removes the SEH record from the chain by restoring `fs:[0]` to the saved `Next` value:

```asm
MOV     ECX, DWORD PTR [EBP - 0x08]    ; load the Next pointer (old fs:[0])
MOV     DWORD PTR fs:[00000000h], ECX  ; restore fs:[0] to previous head
POP     EDI
POP     ESI
POP     EBX
MOV     ESP, EBP
POP     EBP
RETN
```

If the function exits via an exception (rather than normal return), the unwind mechanism handles the unlinking as part of the two-phase unwind (dispatch then unwind).

---

## The Handler Address in the Context of Exploitation

### Normal Use

In legitimate code, the `Handler` field points to one of the C runtime exception handlers:
- `__except_handler3`: older MSVC (VS6 era)
- `__except_handler4`: VS2003 and later, includes stack cookie validation
- `_C_specific_handler`: used in newer MSVC for C-style `__try/__except`
- A user-written handler function

These handlers use the scope table (compiler-generated data) to decide which `__except` filter to evaluate and which `__finally` block to run.

### Exploitation Use

In an SEH overflow, the attacker replaces the `Handler` field with the address of a **`POP POP RETN` gadget** — any sequence of two `POP` instructions followed by `RET` found in a loaded module that does not have SafeSEH protection.

The gadget address must:
- Be in a non-SafeSEH module
- Not contain null bytes (if triggered via string overflow)
- Be at a stable address (preferably in a DLL without ASLR, or use information leak to defeat ASLR)

---

## The POP POP RETN Technique — Detailed Analysis

This is the core pivot mechanism for SEH exploitation. The technique exploits the specific stack layout that exists at the moment an SEH handler is called.

### Stack State at Handler Entry

When `RtlDispatchException` calls the handler, it does so with a standard `CALL` instruction. The `CALL` pushes a return address, then jumps to the handler. Before entering the handler body, the stack contains (from lowest to highest address):

```
esp + 0x00  Return address (inside RtlDispatchException)
esp + 0x04  Pointer to EXCEPTION_RECORD
esp + 0x08  EstablisherFrame = address of EXCEPTION_REGISTRATION_RECORD  ← KEY
esp + 0x0C  Pointer to CONTEXT record
esp + 0x10  DispatcherContext (internal)
```

The value at `esp + 0x08` — `EstablisherFrame` — is a pointer to the very `EXCEPTION_REGISTRATION_RECORD` that was overwritten.

### POP POP RETN Execution Trace

The gadget `POP reg1 / POP reg2 / RET` executes as follows:

```
Initial state:
  ESP = X (pointing at return address on stack)
  EIP = gadget address (our POP POP RETN sequence)

Instruction 1: POP reg1
  reg1 ← [ESP]       ; reg1 = return address (discarded)
  ESP  ← ESP + 4     ; ESP now points at ExceptionRecord ptr

Instruction 2: POP reg2
  reg2 ← [ESP]       ; reg2 = ExceptionRecord ptr (discarded)
  ESP  ← ESP + 4     ; ESP now points at EstablisherFrame

Instruction 3: RET (= POP EIP)
  EIP  ← [ESP]       ; EIP = EstablisherFrame value
  ESP  ← ESP + 4     ; ESP advanced past EstablisherFrame

Result:
  EIP = address of EXCEPTION_REGISTRATION_RECORD (which we control)
```

### Landing at the Controlled Structure

After `RETN`, EIP equals the address of the `EXCEPTION_REGISTRATION_RECORD`. The CPU begins executing bytes at that address. The bytes there are the `Next` field of the record — which the attacker has filled with:

```
\xeb\x06   ; JMP SHORT +6 (skip forward 6 bytes from end of this instruction)
\x90\x90   ; NOP NOP (padding, also makes the Next field 4 bytes total)
```

From the position of `\xeb\x06`, "forward 6 bytes" means: the 2 bytes of the JMP instruction + 4 bytes of the `Handler` field = 6 bytes forward. This puts execution at the byte immediately after the `Handler` field — which is where the attacker places NOPs or shellcode.

### Complete Byte Layout of the Overwritten Region

```
Offset from start of EXCEPTION_REGISTRATION_RECORD:

+0x00  [EB 06]   JMP SHORT +6    ← start of Next field (EIP lands here)
+0x02  [90 90]   NOP NOP          ← padding (completes Next field = 4 bytes)
+0x04  [GG GG GG GG]  Handler = address of POP POP RETN gadget
+0x08  [90 90 90 ...]  NOP sled or shellcode start
```

The `JMP SHORT +6` at offset +0x00 skips over the 4-byte Handler field (offsets +0x04 to +0x07) and the 2-byte relative offset itself. Actually: `JMP SHORT` is encoded as `\xEB\xXX` where `\xXX` is the signed offset from the **next instruction** (i.e., from offset +0x02). To reach offset +0x08 from +0x02, the offset is `0x08 - 0x02 = 0x06`. Hence `\xEB\x06`.

---

## Valid POP Register Combinations

Any two `POP` instructions work because the register destination does not matter — we are discarding the values, not using them:

| Instruction | Opcode | Notes |
|---|---|---|
| `POP EAX` | `58` | Valid |
| `POP ECX` | `59` | Valid |
| `POP EDX` | `5A` | Valid |
| `POP EBX` | `5B` | Valid |
| `POP ESP` | `5C` | **Dangerous** — modifies ESP; avoid |
| `POP EBP` | `5D` | Valid but changes frame pointer |
| `POP ESI` | `5E` | Valid |
| `POP EDI` | `5F` | Valid |

`POP ESP` must be avoided: it would set ESP to whatever value is at the current stack top, corrupting the stack pointer before the second POP executes.

Common real-world gadget sequences searched for:
```
5D 5B C3   POP EBP  / POP EBX  / RETN
5E 5F C3   POP ESI  / POP EDI  / RETN
59 5A C3   POP ECX  / POP EDX  / RETN
58 58 C3   POP EAX  / POP EAX  / RETN
5B 5E C3   POP EBX  / POP ESI  / RETN
```

---

## WinDbg: Examining a Live SEH Frame

### View the SEH Chain

```windbg
!exchain
```

### Manually Inspect a Specific Record

```windbg
; Assume !exchain showed record at 0012FF50
dd 0012FF50 L2
; 0012ff50  0012ff70  7c91e920
;            ^Next     ^Handler (ntdll!_except_handler4)

; Verify the handler is a known legitimate function
ln 7c91e920
; (7c91e920)   ntdll!_except_handler4
```

### After an SEH Overflow — Identify the Overwrite

```windbg
; After crash, examine the SEH chain
!exchain

; If you see something like:
; 0012ff50: 41414141  ← invalid handler address (AAAA)
;   Invalid exception handler

; Check the record
dd 0012ff50 L2
; 0012ff50  ebebeb90  41414141
;            ^Next (corrupted with pattern)  ^Handler (AAAA = uncontrolled overflow)

; Determine offset: subtract the record address from the start of the overflow buffer
; Then use a De Bruijn pattern to find the exact offset to Handler
```

### Set Breakpoint to Watch Handler Being Called

```windbg
bp ntdll!RtlDispatchException
; When hit, inspect the chain:
!exchain
; Then step through to watch which handler gets called
```

---

## Common Mistakes

### Mistake 1: Assuming the SEH Record Is Immediately After the Buffer

The SEH record is not adjacent to the overflow buffer in every case. Between the end of the buffer and the `EXCEPTION_REGISTRATION_RECORD` there may be: other local variables, alignment padding, the saved EBP value, the return address, and sometimes compiler-inserted security cookies. The exact layout depends on the compiler version, optimization flags, and compiler-inserted mitigations. Always verify with a De Bruijn pattern and `!exchain` inspection rather than calculating offsets by hand.

### Mistake 2: Treating the `Next` Field as a Handler Pointer

A common conceptual error: the `Next` field points to the **next `EXCEPTION_REGISTRATION_RECORD`** (another 8-byte structure), not to a handler function. The handler function pointer is always at `+0x04`. When writing the short jump payload, it goes into `Next` (+0x00), and the gadget address goes into `Handler` (+0x04). Getting these swapped produces a crash with EIP landing at a 2-byte jump instruction misinterpreted as a data address.

### Mistake 3: Using a POP ESP in the Gadget

If the gadget sequence contains `POP ESP` (opcode `5C`) as one of the two POPs, execution will not land at the `EXCEPTION_REGISTRATION_RECORD` as expected. `POP ESP` loads the current stack top value (the ExceptionRecord pointer) into ESP, corrupting the stack pointer. The subsequent POP and RETN will operate on wrong stack addresses. Always verify your gadget's full byte sequence before use.

### Mistake 4: Not Verifying the Short Jump Offset

The `\xEB\x06` short jump must be computed from the instruction **after** the jump — which is at offset +0x02 within the record. The destination must reach the first byte after the 4-byte Handler field, which is at offset +0x08. The offset byte is therefore `0x08 - 0x02 = 0x06`. If additional padding or a longer NOP fill is placed in the `Next` field, recalculate accordingly. An off-by-one in the jump offset lands on the second byte of the Handler address or within it, producing an invalid instruction decode.

### Mistake 5: Forgetting That the Record Address Must Be Stack-Range Valid

`RtlDispatchException` validates that each `EXCEPTION_REGISTRATION_RECORD` address lies within the bounds of the current thread's stack (between `StackBase` and `StackLimit` from the TEB). If the corrupted `Next` field points outside the stack range, the dispatcher will reject the record. The attacker's overwritten record at the overflow site is still on the stack, so its address is valid — but if a fake chain is constructed, each `Next` pointer must also fall within stack bounds.
