# SEH Internals — Windows Structured Exception Handling (x86)

## Purpose

This document covers the internal mechanics of Windows Structured Exception Handling (SEH) from the perspective of an exploit developer. SEH is the underlying mechanism that powers C++ `try/catch` blocks, access violation recovery, and — on x86 — a classic stack-based exploitation technique. Understanding SEH at the binary level is a prerequisite for writing reliable SEH-based exploits and for understanding the mitigations designed to stop them.

---

## What SEH Is

Structured Exception Handling is Windows' native mechanism for delivering exception notifications to user-mode code. When the CPU raises a fault (access violation, divide by zero, illegal instruction, stack overflow, etc.), the Windows kernel catches the interrupt, determines whether it occurred in user mode or kernel mode, and dispatches the exception to the appropriate handler chain.

In user mode, on x86, this chain is a singly-linked list of `EXCEPTION_REGISTRATION_RECORD` structures stored on the **current thread's stack**. The head of the chain is stored in `fs:[0x00]` — the first doubleword of the Thread Environment Block (TEB), which the FS segment register points to on x86 Windows.

SEH is not just for C++ exceptions. It is the low-level mechanism beneath:
- C++ `try { } catch { }` (compiled into SEH frames by MSVC)
- Win32 `__try / __except / __finally` constructs
- Stack overflow detection
- Vectored Exception Handling (VEH) — VEH is consulted *before* the SEH chain, but is a separate registration mechanism

**Exploit relevance**: a stack buffer overflow that reaches an `EXCEPTION_REGISTRATION_RECORD` on the stack can overwrite both the `Next` pointer and the `Handler` pointer. If the overflow also triggers an exception (or if an exception can be triggered shortly after the overflow), the OS will walk the corrupted chain and call our overwritten handler address. This is the foundation of SEH-based exploitation.

---

## The SEH Chain Structure

The SEH chain is a linked list rooted at `fs:[0x00]`. Each node is an `EXCEPTION_REGISTRATION_RECORD` — exactly 8 bytes: a `Next` pointer followed by a `Handler` function pointer. The list is terminated by a sentinel node whose `Next` field equals `0xFFFFFFFF`.

```
TEB.ExceptionList  (fs:[0x00])
        │
        ▼
┌──────────────────────────────────────┐
│  EXCEPTION_REGISTRATION_RECORD       │  ← innermost (most-recently registered)
│  +0x00  Next    → next_record_addr   │
│  +0x04  Handler → handler_func_A    │
└──────────────────────────────────────┘
        │
        ▼
┌──────────────────────────────────────┐
│  EXCEPTION_REGISTRATION_RECORD       │
│  +0x00  Next    → next_record_addr   │
│  +0x04  Handler → handler_func_B    │
└──────────────────────────────────────┘
        │
        ▼
┌──────────────────────────────────────┐
│  EXCEPTION_REGISTRATION_RECORD       │  ← outermost (default/thread handler)
│  +0x00  Next    → 0xFFFFFFFF         │  ← chain terminator
│  +0x04  Handler → default_handler   │
└──────────────────────────────────────┘
```

Each time a function that uses `__try` is entered, the compiler-generated prologue **pushes a new record onto the stack** and updates `fs:[0x00]` to point to it. When the function exits (via epilogue), it restores `fs:[0x00]` to the previous record (the `Next` pointer), effectively popping the record off the chain.

This means: SEH records are **on the stack**. They move closer to the stack base as functions nest deeper. A classic stack overflow that fills a buffer and overflows toward higher addresses (toward older frames) will encounter `EXCEPTION_REGISTRATION_RECORD` structures in its overflow path.

---

## Exception Dispatch Flow — Step by Step

When a hardware exception occurs (e.g., a `MOV EAX, [0]` generating a page fault):

### Step 1: CPU Raises the Interrupt

The CPU stops executing the faulting instruction and invokes the interrupt handler for the fault type (e.g., interrupt vector 0x0E for page faults). Control transfers to the kernel's interrupt dispatch table.

### Step 2: Kernel Determines User-Mode vs. Kernel-Mode

The kernel exception handler checks the CS register at the time of the fault. If the CPL (current privilege level) was 3 (user mode), the kernel must transition back to user mode to deliver the exception. It packages the exception information into an `EXCEPTION_RECORD` structure and a `CONTEXT` structure (full CPU register snapshot).

### Step 3: `ntdll!KiUserExceptionDispatcher`

The kernel transitions to user mode by setting the thread's user-mode instruction pointer to `ntdll!KiUserExceptionDispatcher`. This function is a trampoline: it receives the `EXCEPTION_RECORD` and `CONTEXT` structures and begins the user-mode dispatch.

`KiUserExceptionDispatcher` calls `ntdll!RtlDispatchException`.

### Step 4: `RtlDispatchException` Walks the SEH Chain

`RtlDispatchException` reads `fs:[0x00]` to get the head of the chain, then iterates through each `EXCEPTION_REGISTRATION_RECORD`, calling the `Handler` function pointer with four arguments (detailed below).

Before calling each handler, `RtlDispatchException` performs safety checks:
- Validates the registration record address is within the current thread's stack range
- On systems with SafeSEH: validates the handler address is in the module's safe handler list
- On systems with SEHOP: validates the chain terminates at the known ntdll sentinel

### Step 5: Handler Return Values

Each handler function returns one of three values defined in `<excpt.h>`:

| Value | Meaning |
|---|---|
| `ExceptionContinueExecution` (0) | Handler fixed the problem; resume at faulting instruction |
| `ExceptionContinueSearch` (1) | Handler declines; continue walking the chain |
| `ExceptionNestedException` (2) | A nested exception occurred during handling |
| `ExceptionCollidedUnwind` (3) | Used during unwind operations |

If a handler returns `ExceptionContinueSearch`, `RtlDispatchException` moves to the `Next` record and repeats.

### Step 6: Unhandled Exception

If the chain is exhausted (sentinel `0xFFFFFFFF` is reached) without any handler returning `ExceptionContinueExecution`, control passes to `ntdll!RtlpUnhandledExceptionFilter`, which eventually calls the process's unhandled exception filter (`SetUnhandledExceptionFilter`), and if that also fails, terminates the process.

---

## The EXCEPTION_RECORD Structure

When `RtlDispatchException` calls each handler, it passes a pointer to an `EXCEPTION_RECORD`. This structure describes what happened:

```c
typedef struct _EXCEPTION_RECORD {
    DWORD  ExceptionCode;           // +0x00: what fault occurred
    DWORD  ExceptionFlags;          // +0x04: CONTINUABLE (0) or NONCONTINUABLE (1)
    struct _EXCEPTION_RECORD *ExceptionRecord; // +0x08: chained exception (nested)
    PVOID  ExceptionAddress;        // +0x0C: address where the fault occurred
    DWORD  NumberParameters;        // +0x10: number of ExceptionInformation entries
    ULONG_PTR ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS]; // +0x14
} EXCEPTION_RECORD;
```

### ExceptionCode Values Relevant to Exploitation

| Code | Constant | Meaning |
|---|---|---|
| `0xC0000005` | `STATUS_ACCESS_VIOLATION` | Read/write to unmapped or protected memory |
| `0x80000001` | `STATUS_GUARD_PAGE_VIOLATION` | First access to a guard page |
| `0xC0000094` | `STATUS_INTEGER_DIVIDE_BY_ZERO` | DIV or IDIV with zero divisor |
| `0xC0000096` | `STATUS_PRIVILEGED_INSTRUCTION` | Ring-0 instruction in ring-3 |
| `0xC000001D` | `STATUS_ILLEGAL_INSTRUCTION` | Undefined opcode (e.g., `UD2`) |
| `0xC00000FD` | `STATUS_STACK_OVERFLOW` | Stack guard page hit |
| `0x80000003` | `STATUS_BREAKPOINT` | `INT 3` breakpoint |
| `0x80000004` | `STATUS_SINGLE_STEP` | Single-step debug trap |

For `STATUS_ACCESS_VIOLATION` (0xC0000005), `ExceptionInformation[0]` holds the access type (0=read, 1=write, 8=DEP execute) and `ExceptionInformation[1]` holds the faulting address.

---

## The Four-Argument Handler Calling Convention

When `RtlDispatchException` invokes an SEH handler, it uses the standard x86 `__cdecl` calling convention with four arguments pushed right to left:

```c
EXCEPTION_DISPOSITION __cdecl handler(
    EXCEPTION_RECORD *ExceptionRecord,   // [esp+0x04] after CALL
    void             *EstablisherFrame,  // [esp+0x08] — critical for exploitation
    CONTEXT          *ContextRecord,     // [esp+0x0C]
    void             *DispatcherContext  // [esp+0x10]
);
```

### Stack Layout During Handler Invocation

At the moment the handler begins executing (after the `CALL` to the handler address), the stack looks like this:

```
High addresses
┌─────────────────────────────────────┐
│  DispatcherContext ptr   [esp+0x10] │  internal dispatcher state
├─────────────────────────────────────┤
│  ContextRecord ptr       [esp+0x0C] │  full CPU state (CONTEXT struct)
├─────────────────────────────────────┤
│  EstablisherFrame ptr    [esp+0x08] │  ← address of the EXCEPTION_REGISTRATION_RECORD
├─────────────────────────────────────┤
│  ExceptionRecord ptr     [esp+0x04] │  ← describes the exception
├─────────────────────────────────────┤
│  Return address          [esp+0x00] │  ← back into RtlDispatchException
└─────────────────────────────────────┘
Low addresses (stack grows down)
```

### Why EstablisherFrame Is Critical for Exploitation

`EstablisherFrame` at `[esp+0x08]` is a pointer to the `EXCEPTION_REGISTRATION_RECORD` that registered this handler. This means it points to the **structure that was overwritten during the stack overflow**. Specifically:

- `[EstablisherFrame + 0x00]` is the `Next` field (which we control)
- `[EstablisherFrame + 0x04]` is the `Handler` field (which we set to the POP POP RETN gadget address)

The `POP POP RETN` technique exploits this layout: two POPs discard the return address and ExceptionRecord pointer, and then RETN pops `[esp+0x08]` (EstablisherFrame) into EIP. Execution lands at the start of the `EXCEPTION_REGISTRATION_RECORD` structure — right at our controlled `Next` field content. See `SEH_Exploitation.md` for the full walkthrough.

---

## How Compilers Generate SEH Frames

When MSVC compiles a function containing `__try`, the prologue registers an SEH frame:

```asm
; Typical MSVC SEH prologue (simplified)
PUSH    handler_address         ; push handler function pointer
PUSH    DWORD PTR fs:[0]        ; push current chain head (becomes Next)
MOV     DWORD PTR fs:[0], ESP   ; set fs:[0] to point to our record
SUB     ESP, local_var_size     ; allocate locals
```

After this prologue, the stack at `fs:[0]` points to:
```
[esp + offset + 0x00] = old fs:[0]   (Next field)
[esp + offset + 0x04] = handler_addr  (Handler field)
```

The epilogue (on normal function exit) restores `fs:[0]`:
```asm
MOV     ECX, DWORD PTR [EBP - offset]   ; load the saved Next pointer
MOV     DWORD PTR fs:[0], ECX           ; restore chain head
```

For MSVC's extended `__except` frames (which include a scope table for nested try levels), the record is larger — it begins with the standard 8-byte `EXCEPTION_REGISTRATION_RECORD` followed by a scope table pointer, try level indicator, and other compiler-specific fields. The OS only reads the first 8 bytes for dispatch purposes.

---

## SafeSEH: OS-Level Validation of Handler Addresses

Introduced with Windows XP SP2 and MSVC /GS+ (Visual C++ 2003), SafeSEH adds a **valid handler table** to PE images. When the linker builds a SafeSEH-aware image, it embeds a sorted list of valid exception handler addresses in the `IMAGE_LOAD_CONFIG_DIRECTORY` structure (specifically in `SEHandlerTable` and `SEHandlerCount`).

Before calling any SEH handler, `RtlDispatchException` checks:
1. Is the module containing the handler address marked as SafeSEH-aware?
2. If yes, is the handler address in the `SEHandlerTable`?
3. If not in the table, refuse to call it.

```c
// Pseudocode of the check inside RtlDispatchException
if (module_has_safe_seh_table(handler_address)) {
    if (!handler_in_safe_seh_table(handler_address)) {
        // Chain validation failure — terminate process
        RtlRaiseStatus(STATUS_INVALID_EXCEPTION_HANDLER);
    }
}
```

**Bypass**: The check only applies to modules that **have** a SafeSEH table. Any module compiled without `/SAFESEH` (or old DLLs without the table) is not checked. An attacker finds a `POP POP RETN` gadget in such a module. Common targets historically: legacy COM DLLs, third-party libraries compiled without /SAFESEH.

**WinDbg check**: `!nmod` lists modules and flags those without SafeSEH protection.

---

## SEHOP: SEH Overwrite Protection

Introduced in Windows Vista SP1, SEHOP (Structured Exception Handling Overwrite Protection) validates the **structural integrity of the entire SEH chain** before dispatching any exception.

### How SEHOP Works

When an exception is about to be dispatched, the OS walks the entire SEH chain forward, following every `Next` pointer. If the chain does not terminate at `ntdll!FinalExceptionHandlerPad` (a known sentinel record registered at thread creation time in ntdll), SEHOP considers the chain corrupted and terminates the process.

The sentinel node has a known address (varies per OS version but is predictable within a given process). SEHOP requires that the last `Next` pointer in the attacker's chain equals this sentinel address.

### Bypass Techniques

1. **Information leak + fake terminus**: if the attacker can read the sentinel address from the TEB or from ntdll memory, they can include it as the `Next` field of their last fake record.

2. **Heap spray to place a valid-looking record**: if the attacker sprays the heap with data that looks like a valid SEH chain ending in the sentinel, and the `Next` field of the overwritten record points into that sprayed region, SEHOP validation may pass.

3. **SEHOP is disabled for some processes**: older compatibility flags (`PROCESS_MITIGATION_POLICY`) disable SEHOP for specific executables. Check `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<exe>\DisableExceptionChainValidation`.

---

## x86 vs. x64: Architectural Difference

**x86**: SEH uses the linked list on the stack (fs:[0x00] chain). Stack-based overflow exploitation is possible because handler addresses are stored inline on the stack.

**x64**: SEH is **table-based**, not stack-based. Exception handler information is stored in the `.pdata` section of each PE image as `RUNTIME_FUNCTION` records. These records describe the address ranges covered by each function and point to unwind information in `.xdata`. The OS reads these static tables to determine which handler applies to a given instruction address — there is no writable linked list on the stack.

Consequences for exploitation:
- You cannot overwrite an SEH handler by overflowing a stack buffer on x64 — there is no handler pointer on the stack to overwrite.
- Stack overflow exploits on x64 must rely on overwriting return addresses or other control-flow data.
- The classic `POP POP RETN` SEH technique **does not exist on x64**.
- `fs:[0x00]` on x64 is not the SEH chain (it is still the TEB, but the SEH mechanism is different). The GS register points to the TEB on x64.

The reason is architectural: x64's 64-bit address space and AMD64 ABI requirements led Microsoft to implement a more robust, non-stack-stored exception dispatch mechanism that also enables reliable stack unwinding.

---

## WinDbg Verification Workflows

### Display the Current SEH Chain

```windbg
!exchain
```

Output example:
```
0:000> !exchain
0012ff70: ntdll!_except_handler4+0 (7c91e920)
  CRT scope  0, filter: ntdll!__RtlUserThreadStart+1a284 (7c966e00)
                func:   ntdll!__RtlUserThreadStart+1a2a0 (7c966e1c)
0012ffe0: kernel32!_except_handler3+0 (7c839ac0)
  CRT scope  0, filter: kernel32!BaseThreadInitThunk+18 (7c8369dc)
                func:   kernel32!BaseThreadInitThunk+20 (7c8369e4)
0012fff0: kernel32!FinalExceptionHandler+0 (7c862e30)
```

### Manually Walk the SEH Chain

```windbg
; Read the head of the chain from fs:[0]
dd fs:[0] L1

; Output: 0012ff70  (head of chain)

; Read that record
dd 0012ff70 L2
; Output:
; 0012ff70  0012ffe0  7c91e920
;            ^Next     ^Handler

; Follow Next
dd 0012ffe0 L2
; 0012ffe0  0012fff0  7c839ac0

; Follow again
dd 0012fff0 L2
; 0012fff0  ffffffff  7c862e30   ← terminator
```

### Shorthand: Follow the Chain with poi()

```windbg
; poi() dereferences a pointer
dd poi(fs:[0])          ; first record
dd poi(poi(fs:[0]))     ; second record
```

### Display the Current Exception Record

```windbg
.exr @$exr             ; display current exception record
.cxr @$cxr             ; display context record (register state at exception)
```

### Set a Breakpoint on Exception Dispatch

```windbg
bp ntdll!RtlDispatchException
bp ntdll!KiUserExceptionDispatcher
```

### Find Modules Without SafeSEH

```windbg
!nmod                   ; list non-safeseh modules
```

---

## Common Mistakes

### Mistake 1: Confusing VEH and SEH

Vectored Exception Handling (VEH) is consulted **before** the SEH chain. VEH handlers are registered with `AddVectoredExceptionHandler` and are stored in a doubly-linked list in the process heap — **not** on the stack, and not in `fs:[0x00]`. SEH overflows do not overwrite VEH records. An exploit that triggers an exception and expects to hit an SEH handler may instead hit a VEH handler registered by a DRM or anti-cheat system, which can terminate the process before the SEH chain is consulted.

### Mistake 2: Forgetting the Exception Must Actually Be Triggered

Overwriting an SEH record does nothing unless an exception is actually raised. A common error in exploit development is overflowing into the SEH record but then having the function return normally (without faulting), so the SEH chain is never walked. The overflow must either naturally trigger an access violation (by writing past valid memory) or the exploit must ensure an exception occurs (e.g., writing beyond a mapped region, null pointer dereference in code following the overflow).

### Mistake 3: Wrong Offset to the SEH Record

The SEH record is not immediately after the overflow buffer. There is typically padding between the end of the buffer and the `EXCEPTION_REGISTRATION_RECORD` — local variables, saved EBP, possibly canaries, alignment bytes. Using an incorrect offset causes the `Handler` field to receive padding bytes rather than the gadget address. Always use a cyclic/De Bruijn pattern and inspect `!exchain` after the crash to identify the exact offset.

### Mistake 4: Choosing a Gadget in a SafeSEH-Protected Module

The `POP POP RETN` gadget address must reside in a module that does **not** have a SafeSEH table, otherwise `RtlDispatchException` will reject the handler and not call it. Beginners often pick gadgets from the main executable or a common DLL that happens to have SafeSEH enabled.

### Mistake 5: Not Accounting for NULL Bytes in the Gadget Address

If the exploit is triggered via a string-based overflow (e.g., `strcpy`, `gets`), the gadget address cannot contain a null byte (0x00) anywhere in it, since the string copy will terminate at the first null. This limits which POP POP RETN gadgets are usable. Always verify the address is null-byte free before using it.
