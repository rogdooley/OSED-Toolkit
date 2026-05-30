# CONTEXT — CPU State Snapshot (`_CONTEXT`)

## Purpose

`_CONTEXT` is the complete CPU state snapshot taken at the moment an exception occurs. When an exception is raised, the Windows kernel saves a `CONTEXT` record on the user-mode stack (within `KiUserExceptionDispatcher`) before calling user-mode exception handlers. This record captures the full CPU state — all general-purpose registers, segment registers, the instruction pointer, the stack pointer, flags, and floating-point/SSE state — at the instant the fault occurred.

After all exception handlers have run, if any handler returns `ExceptionContinueExecution`, the dispatcher (`ntdll!RtlRestoreContext` or `ntdll!ZwContinue`) restores the (possibly modified) `CONTEXT` record back into the CPU. This is the mechanism that allows exception handlers to fix up faults and resume execution from a corrected state.

`CONTEXT` is also used outside of exception handling:
- `GetThreadContext` / `NtGetContextThread` — reads a suspended thread's CPU state into a `CONTEXT`
- `SetThreadContext` / `NtSetContextThread` — writes a `CONTEXT` record into a suspended thread, updating its CPU state
- `RtlCaptureContext` — saves the calling thread's current state without raising an exception
- `SetThreadContext` on a thread at its start address — the classic thread-hijack injection technique

---

## Exploit Relevance

### SEH Exploitation

Structured Exception Handling (SEH) exploitation on x86 traditionally overwrites `EXCEPTION_REGISTRATION_RECORD.Handler` with a pointer to shellcode (or a gadget). When the corrupted handler is called, the exploit must land execution in the shellcode. More advanced SEH exploits go further: by controlling the stack layout, an attacker can position the corrupted data to also overwrite the `CONTEXT` record that the kernel placed on the stack during dispatch. Modifying `CONTEXT.Eip` and `CONTEXT.Esp` before the handler returns `ExceptionContinueExecution` causes the dispatcher to resume at the attacker-chosen address with the attacker-chosen stack — full control.

### Debugger Detection via Hardware Breakpoints

Hardware breakpoints (set by a debugger via the DR registers) are stored per-thread. Calling `GetThreadContext` on the current thread and reading `Dr0` through `Dr3` reveals whether any hardware breakpoints are currently set. This is more reliable than checking `IsBeingDebugged` because hardware breakpoints can be active even when the `IsBeingDebugged` byte is manually cleared.

### Anti-Analysis via VEH

A Vectored Exception Handler (VEH) receives an `EXCEPTION_POINTERS` structure containing both an `EXCEPTION_RECORD*` and a `CONTEXT*`. By modifying `CONTEXT.Eip` in the VEH handler and returning `EXCEPTION_CONTINUE_EXECUTION`, shellcode can redirect the faulting instruction to skip over it, hide opaque predicates, or implement a simple single-step emulation loop.

### Process Injection via SetThreadContext

The classic "Ghost Writing" and thread-hijacking injection techniques work as follows:
1. Open or create a target process and a suspended thread
2. Call `VirtualAllocEx` to allocate space for shellcode
3. Call `WriteProcessMemory` to write shellcode
4. Call `GetThreadContext` to capture the thread's current `CONTEXT`
5. Set `Context.Eip` (x86) or `Context.Rip` (x64) to the shellcode address
6. Call `SetThreadContext` with the modified `CONTEXT`
7. Call `ResumeThread` — the thread begins executing at the shellcode address

---

## Full x86 CONTEXT Structure

Total size: **0x2CC bytes (716 bytes)**

| Field | Offset (hex) | Offset (dec) | Type | Size | Purpose |
|---|---|---|---|---|---|
| `ContextFlags` | +0x000 | 0 | DWORD | 4 | Bitmask indicating which groups of fields are valid |
| `Dr0` | +0x004 | 4 | DWORD | 4 | Hardware breakpoint address register 0 |
| `Dr1` | +0x008 | 8 | DWORD | 4 | Hardware breakpoint address register 1 |
| `Dr2` | +0x00C | 12 | DWORD | 4 | Hardware breakpoint address register 2 |
| `Dr3` | +0x010 | 16 | DWORD | 4 | Hardware breakpoint address register 3 |
| `Dr6` | +0x014 | 20 | DWORD | 4 | Debug status register (which breakpoint fired) |
| `Dr7` | +0x018 | 24 | DWORD | 4 | Debug control register (enables/configures DR0-DR3) |
| `FloatSave` | +0x01C | 28 | FLOATING_SAVE_AREA | 112 | x87 FPU state (ControlWord, StatusWord, TagWord, registers) |
| `SegGs` | +0x08C | 140 | DWORD | 4 | GS segment register |
| `SegFs` | +0x090 | 144 | DWORD | 4 | FS segment register (points to TEB in user mode) |
| `SegEs` | +0x094 | 148 | DWORD | 4 | ES segment register |
| `SegDs` | +0x098 | 152 | DWORD | 4 | DS segment register |
| `Edi` | +0x09C | 156 | DWORD | 4 | EDI general-purpose register |
| `Esi` | +0x0A0 | 160 | DWORD | 4 | ESI general-purpose register |
| `Ebx` | +0x0A4 | 164 | DWORD | 4 | EBX general-purpose register |
| `Edx` | +0x0A8 | 168 | DWORD | 4 | EDX general-purpose register |
| `Ecx` | +0x0AC | 172 | DWORD | 4 | ECX general-purpose register |
| `Eax` | +0x0B0 | 176 | DWORD | 4 | EAX general-purpose register |
| `Ebp` | +0x0B4 | 180 | DWORD | 4 | EBP frame pointer register |
| `Eip` | +0x0B8 | 184 | DWORD | 4 | Instruction pointer — KEY for exploitation |
| `SegCs` | +0x0BC | 188 | DWORD | 4 | CS (code segment) register |
| `EFlags` | +0x0C0 | 192 | DWORD | 4 | CPU flags register (carry, zero, sign, overflow, etc.) |
| `Esp` | +0x0C4 | 196 | DWORD | 4 | Stack pointer — KEY for exploitation |
| `SegSs` | +0x0C8 | 200 | DWORD | 4 | SS (stack segment) register |
| `ExtendedRegisters` | +0x0CC | 204 | BYTE[512] | 512 | SSE/XMM state (FXSAVE format, for CONTEXT_EXTENDED_REGISTERS) |

### Key field locations at a glance

```
CONTEXT.Eip  is at offset +0x0B8  (188 decimal)
CONTEXT.Esp  is at offset +0x0C4  (196 decimal)
CONTEXT.Eax  is at offset +0x0B0  (176 decimal)
CONTEXT.Ebx  is at offset +0x0A4  (164 decimal)
CONTEXT.Dr0  is at offset +0x004  (4 decimal)
```

### FLOATING_SAVE_AREA Layout (at CONTEXT+0x01C)

```
FLOATING_SAVE_AREA (112 bytes):
  +0x00  ControlWord    DWORD   FPU control word
  +0x04  StatusWord     DWORD   FPU status word
  +0x08  TagWord        DWORD   FPU tag word
  +0x0C  ErrorOffset    DWORD   FPU CS selector
  +0x10  ErrorSelector  DWORD   FPU CS offset of faulting instruction
  +0x14  DataOffset     DWORD   FPU DS offset
  +0x18  DataSelector   DWORD   FPU DS selector
  +0x1C  RegisterArea   BYTE[80] eight 10-byte x87 FP registers (ST0-ST7)
  +0x6C  Cr0NpxState    DWORD   CR0.NE bit / NPX state
```

Total: 0x70 bytes = 112 bytes. `FloatSave` at `CONTEXT+0x01C`, so the segment registers begin at `0x01C + 0x70 = 0x08C`.

---

## ContextFlags Values

`ContextFlags` is a bitmask that tells `GetThreadContext`/`SetThreadContext` which groups of registers to read or write. The high word (`0x0001xxxx`) is the architecture identifier for x86. Any field not covered by the flags mask may contain stale or zeroed data.

| Value | Name | Fields Covered |
|---|---|---|
| `0x00010000` | `CONTEXT_i386` | Architecture identifier only — no fields |
| `0x00010001` | `CONTEXT_CONTROL` | Ebp, Eip, SegCs, EFlags, Esp, SegSs |
| `0x00010002` | `CONTEXT_INTEGER` | Eax, Ebx, Ecx, Edx, Esi, Edi |
| `0x00010004` | `CONTEXT_SEGMENTS` | SegGs, SegFs, SegEs, SegDs |
| `0x00010008` | `CONTEXT_FLOATING_POINT` | FloatSave |
| `0x00010010` | `CONTEXT_DEBUG_REGISTERS` | Dr0, Dr1, Dr2, Dr3, Dr6, Dr7 |
| `0x00010020` | `CONTEXT_EXTENDED_REGISTERS` | ExtendedRegisters (SSE/XMM via FXSAVE) |
| `0x00010007` | `CONTEXT_FULL` | CONTEXT_CONTROL \| CONTEXT_INTEGER \| CONTEXT_SEGMENTS |
| `0x0001003F` | `CONTEXT_ALL` | All groups |

### Why ContextFlags matters

When a handler receives a `CONTEXT*`:
- If `ContextFlags` does not include `CONTEXT_DEBUG_REGISTERS`, the `Dr0`-`Dr3` fields contain undefined data — reading them for breakpoint detection gives false results
- When calling `GetThreadContext`, you must set `ContextFlags` before the call to specify what to retrieve; fields outside the requested groups are untouched
- When calling `SetThreadContext`, only fields covered by `ContextFlags` are written to the thread; other fields retain their previous values
- A caller that forgets to set `ContextFlags` before `GetThreadContext` may receive all-zero fields or trigger an error on some Windows versions

```nasm
; Correct usage: allocate CONTEXT on stack, set ContextFlags, then call
sub  esp, 0x2CC                  ; reserve 716 bytes for CONTEXT
mov  esi, esp                    ; ESI = &CONTEXT
xor  eax, eax
mov  ecx, 0x2CC / 4
rep  stosd                       ; zero the entire CONTEXT structure
mov  dword [esi], 0x0001003F     ; ContextFlags = CONTEXT_ALL
push esi                         ; lpContext
push 0xFFFFFFFF                  ; hThread = current thread (pseudo-handle)
call dword [GetThreadContext]    ; call API
; Now all fields are valid
```

---

## Stack Layout During SEH Exception Dispatch

Understanding the stack layout when an SEH handler is called is essential for exploiting SEH overflows.

### Sequence of events

1. A fault occurs (access violation, divide-by-zero, etc.)
2. The CPU switches to ring 0 and calls the kernel exception handler
3. The kernel transitions back to user mode and calls `ntdll!KiUserExceptionDispatcher`
4. `KiUserExceptionDispatcher` places an `EXCEPTION_RECORD` and a `CONTEXT` on the user-mode stack (at the thread's current `ESP` at the time of the fault)
5. `ntdll!RtlDispatchException` walks the SEH chain stored at `FS:[0x00]` (which points to the innermost `EXCEPTION_REGISTRATION_RECORD` on the thread stack)
6. For each registered handler, the dispatcher calls it with the following stack frame:

### Handler call stack frame

```
; Stack when a classic Win32 SEH handler is called:
;
;   ESP+0x00  ReturnAddress         DWORD  return address back to RtlDispatchException trampoline
;   ESP+0x04  EXCEPTION_RECORD*     DWORD  pointer to EXCEPTION_RECORD structure
;   ESP+0x08  EstablisherFrame*     DWORD  pointer to the EXCEPTION_REGISTRATION_RECORD for this handler
;   ESP+0x0C  CONTEXT*              DWORD  pointer to CONTEXT record (stored higher on the stack)
;   ESP+0x10  DispatcherContext*    DWORD  internal dispatcher context (can be NULL for SEH)
```

The `CONTEXT` record is not at `ESP+0x0C` itself — that slot contains a **pointer** to the `CONTEXT`. The actual `CONTEXT` structure was pushed earlier during `KiUserExceptionDispatcher` setup and lives at a higher stack address (closer to the thread's stack base).

### Memory Layout Diagram

```
Thread stack, growing downward (lower addresses at bottom):

  Lower addresses (toward ESP)
  ┌────────────────────────────────────────────────────────────┐
  │  [Handler frame]                                           │
  │  ESP+0x00  return address to dispatcher                    │
  │  ESP+0x04  EXCEPTION_RECORD* ──────────────────────────┐   │
  │  ESP+0x08  EstablisherFrame* (= &EXCEPTION_REG_RECORD)  │   │
  │  ESP+0x0C  CONTEXT* ───────────────────────────────┐   │   │
  │  ESP+0x10  DispatcherContext*                       │   │   │
  ├────────────────────────────────────────────────────│───│───┤
  │  [Some gap depending on call chain depth]           │   │   │
  ├────────────────────────────────────────────────────│───│───┤
  │  [EXCEPTION_RECORD ~ 80 bytes] <───────────────────┼───┘   │
  │    +0x00  ExceptionCode    DWORD                   │       │
  │    +0x04  ExceptionFlags   DWORD                   │       │
  │    +0x08  ExceptionRecord* DWORD (chained)         │       │
  │    +0x0C  ExceptionAddress DWORD (faulting EIP)    │       │
  │    +0x10  NumberParameters DWORD                   │       │
  │    +0x14  ExceptionInfo[15] DWORD[15]              │       │
  ├────────────────────────────────────────────────────│───────┤
  │  [CONTEXT = 0x2CC bytes] <─────────────────────────┘       │
  │    +0x000  ContextFlags                                     │
  │    +0x004  Dr0 ... Dr7                                      │
  │    +0x01C  FloatSave                                        │
  │    +0x08C  Segment registers                                │
  │    +0x09C  Edi, Esi, Ebx, Edx, Ecx, Eax, Ebp              │
  │    +0x0B8  Eip  ← overwriting this redirects execution     │
  │    +0x0BC  SegCs                                            │
  │    +0x0C0  EFlags                                           │
  │    +0x0C4  Esp  ← overwriting this pivots the stack        │
  │    +0x0C8  SegSs                                            │
  │    +0x0CC  ExtendedRegisters[512]                           │
  ├────────────────────────────────────────────────────────────┤
  │  [Stack frame that triggered the exception]                 │
  │  (EXCEPTION_REGISTRATION_RECORD is here: Handler + Next)   │
  │  ← this is what the overflow corrupted to reach here       │
  Upper addresses (toward stack base / lower ESP values before fault)
  └────────────────────────────────────────────────────────────┘
```

### SEH Overflow to CONTEXT Overwrite

A classic stack-based buffer overflow overwrites the `EXCEPTION_REGISTRATION_RECORD.Handler` field. An extended overflow can reach further up the stack (toward higher addresses, since the CONTEXT was pushed before the handler call) and overwrite the `CONTEXT` record itself. The offset from the `EXCEPTION_REGISTRATION_RECORD` to the `CONTEXT` depends on the specific call stack depth and stack frame sizes when the overflow occurs — it must be determined empirically (e.g., in a debugger).

When both overflows succeed:
1. `Handler` is set to a `pop/pop/ret` gadget (or directly to shellcode on older Windows with no SafeSEH)
2. `CONTEXT.Eip` is set to the shellcode address
3. `CONTEXT.Esp` is set to a writable location (or left valid)
4. The handler is called, the gadget executes, eventually the handler returns `EXCEPTION_CONTINUE_EXECUTION (-1)`
5. `RtlRestoreContext` loads the modified `CONTEXT` — CPU begins executing at `CONTEXT.Eip`

---

## Assembly: Hardware Breakpoint Detection via GetThreadContext

This technique checks whether a debugger has set hardware breakpoints on the current thread.

```nasm
; detect_hardware_bp:
;   Returns: ZF=1 if no hardware breakpoints, ZF=0 if any are set
;   Requires: GetThreadContext address already resolved in [ebp+GetThreadContext_ptr]

detect_hardware_bp:
    ; Allocate CONTEXT on stack (0x2CC = 716 bytes)
    sub  esp, 0x2CC                  ; reserve space for CONTEXT
    mov  esi, esp                    ; ESI = &CONTEXT (base address of buffer)

    ; Zero the CONTEXT structure
    push edi
    push ecx
    mov  edi, esi                    ; destination
    xor  eax, eax                    ; fill value = 0
    mov  ecx, 0x2CC                  ; byte count
    rep  stosb                       ; zero fill
    pop  ecx
    pop  edi

    ; Set ContextFlags = CONTEXT_ALL to request all register groups
    ; including CONTEXT_DEBUG_REGISTERS (0x10)
    mov  dword [esi + 0x000], 0x0001003F  ; ContextFlags = CONTEXT_ALL

    ; Call GetThreadContext(GetCurrentThread(), &CONTEXT)
    ; GetCurrentThread() pseudo-handle = -1 = 0xFFFFFFFF
    push esi                         ; lpContext = &CONTEXT
    push 0xFFFFFFFF                  ; hThread = current thread pseudo-handle
    call dword [ebp + GetThreadContext_ptr]

    ; Check return value: EAX = 0 means failure
    test eax, eax
    jz   .detect_bp_fail

    ; Read Dr0, Dr1, Dr2, Dr3 and OR them together
    ; CONTEXT.Dr0 = +0x004, Dr1 = +0x008, Dr2 = +0x00C, Dr3 = +0x010
    mov  eax, dword [esi + 0x004]    ; Dr0
    or   eax, dword [esi + 0x008]    ; Dr1
    or   eax, dword [esi + 0x00C]    ; Dr2
    or   eax, dword [esi + 0x010]    ; Dr3
    ; EAX = 0 only if all four debug address registers are zero (no hardware BPs)
    test eax, eax
    ; ZF=1 → no hardware breakpoints (clean)
    ; ZF=0 → at least one hardware breakpoint is set (debugger present)

.detect_bp_done:
    add  esp, 0x2CC                  ; restore stack
    ret

.detect_bp_fail:
    ; GetThreadContext failed — treat as no debugger to avoid false positives
    xor  eax, eax                    ; set ZF=1
    jmp  .detect_bp_done
```

Note: `Dr6` (debug status) and `Dr7` (debug control) are not checked here — checking only `Dr0`-`Dr3` is sufficient to detect the presence of breakpoint addresses. A debugger that sets `Dr7` but clears `Dr0`-`Dr3` is not actively watching any address.

---

## Assembly: Modifying CONTEXT in a Vectored Exception Handler

A VEH handler receives `EXCEPTION_POINTERS*`, which contains both `ExceptionRecord` and `ContextRecord` pointers.

```nasm
; VEH Handler:
;   Prototype: LONG NTAPI VehHandler(PEXCEPTION_POINTERS pExcInfo);
;   On entry: [esp+4] = EXCEPTION_POINTERS*
;
;   EXCEPTION_POINTERS layout:
;     +0x00  ExceptionRecord   DWORD  pointer to EXCEPTION_RECORD
;     +0x04  ContextRecord     DWORD  pointer to CONTEXT
;
;   Return values:
;     -1 (0xFFFFFFFF) = EXCEPTION_CONTINUE_EXECUTION  (resume, using modified CONTEXT)
;      0 (0x00000000) = EXCEPTION_CONTINUE_SEARCH      (pass to next handler)

veh_handler:
    push ebp
    mov  ebp, esp

    ; Load EXCEPTION_POINTERS* from parameter
    mov  eax, dword [ebp + 8]        ; eax = EXCEPTION_POINTERS*

    ; Load ExceptionRecord* (optional: check exception code)
    mov  edx, dword [eax + 0]        ; edx = EXCEPTION_RECORD*
    mov  edx, dword [edx + 0]        ; edx = ExceptionRecord.ExceptionCode
    cmp  edx, 0xC0000005             ; is it ACCESS_VIOLATION?
    jne  .pass_on                    ; no → let next handler deal with it

    ; Load ContextRecord*
    mov  ecx, dword [eax + 4]        ; ecx = CONTEXT*

    ; Patch CONTEXT.Eip to skip past the faulting instruction
    ; (assumes faulting instruction is 2 bytes; adjust as needed)
    mov  edx, dword [ecx + 0x0B8]   ; edx = current Eip from CONTEXT
    add  edx, 2                      ; advance past 2-byte faulting instruction
    mov  dword [ecx + 0x0B8], edx   ; write new Eip back to CONTEXT

    ; Alternatively: redirect to a specific address
    ; mov  dword [ecx + 0x0B8], 0x00401234   ; hard-coded redirect target

    ; Optionally fix up a register: set EAX = 0 in the resumed context
    mov  dword [ecx + 0x0B0], 0     ; CONTEXT.Eax = 0

    ; Return EXCEPTION_CONTINUE_EXECUTION
    mov  eax, -1                     ; 0xFFFFFFFF
    pop  ebp
    ret  4                           ; stdcall: clean up 4 bytes of arguments

.pass_on:
    ; Return EXCEPTION_CONTINUE_SEARCH
    xor  eax, eax
    pop  ebp
    ret  4
```

### VEH for opaque predicate defeat

Some anti-disassembly techniques use intentional faults (e.g., read from address 0, divide by zero) as opaque predicates — they always fault, the VEH skips the instruction, and the real code follows. A VEH registered early in startup can handle these transparently:

```nasm
veh_opaque_predicate_handler:
    mov  eax, dword [esp + 4]        ; EXCEPTION_POINTERS*
    mov  ecx, dword [eax + 4]        ; CONTEXT*

    ; Advance Eip by 1 byte (for one-byte INT 3 or HLT) or 2 bytes (for fault instructions)
    inc  dword [ecx + 0x0B8]         ; Eip += 1

    mov  eax, -1                     ; EXCEPTION_CONTINUE_EXECUTION
    ret  4
```

---

## Assembly: Thread Hijacking via SetThreadContext

```nasm
; Hijack a suspended thread's execution via SetThreadContext
; Assumes:
;   EBX = target thread HANDLE (already open with THREAD_SET_CONTEXT | THREAD_GET_CONTEXT)
;   ECX = address to redirect execution to (shellcode / payload)
;   ESI = resolved address of GetThreadContext
;   EDI = resolved address of SetThreadContext

thread_hijack:
    ; Allocate CONTEXT on stack
    sub  esp, 0x2CC
    mov  eax, esp                    ; EAX = &CONTEXT

    ; Zero and set ContextFlags
    push eax
    xor  edx, edx
    mov  ecx, 0x2CC / 4
.zero_ctx:
    mov  dword [eax + ecx*4 - 4], edx
    loop .zero_ctx
    pop  eax
    mov  dword [eax], 0x00010007    ; ContextFlags = CONTEXT_FULL (control + integer + segments)

    ; Call GetThreadContext(hThread, &CONTEXT)
    push eax                         ; lpContext
    push ebx                         ; hThread
    call esi                         ; GetThreadContext

    test eax, eax
    jz   .hijack_fail

    ; Modify Eip in the CONTEXT
    mov  eax, esp                    ; &CONTEXT (still on stack)
    mov  dword [eax + 0x0B8], ecx   ; CONTEXT.Eip = shellcode address

    ; Optionally align Esp to avoid alignment issues in shellcode
    ; (leave it as-is if shellcode handles its own stack setup)

    ; Call SetThreadContext(hThread, &CONTEXT)
    push eax                         ; lpContext
    push ebx                         ; hThread
    call edi                         ; SetThreadContext

    ; Return: EAX = 1 on success
    add  esp, 0x2CC
    ret

.hijack_fail:
    add  esp, 0x2CC
    xor  eax, eax
    ret
```

---

## Debug Registers: Dr6 and Dr7

Though less commonly used in basic shellcode, understanding `Dr6` and `Dr7` is important for anti-anti-debug work.

### Dr7 — Debug Control Register

```
Dr7 bitfield:
  Bits 1:0   (L0, G0)  — local/global enable for DR0 breakpoint
  Bits 3:2   (L1, G1)  — local/global enable for DR1 breakpoint
  Bits 5:4   (L2, G2)  — local/global enable for DR2 breakpoint
  Bits 7:6   (L3, G3)  — local/global enable for DR3 breakpoint
  Bits 17:16 (R/W0, LEN0) — condition (execute/write/read+write) and size for DR0
  Bits 21:18 (R/W1, LEN1) — condition and size for DR1
  Bits 25:22 (R/W2, LEN2) — condition and size for DR2
  Bits 29:26 (R/W3, LEN3) — condition and size for DR3

  R/W field values:
    00 = break on instruction execution (only valid when LEN=00)
    01 = break on data write
    10 = break on I/O read/write (requires CR4.DE=1, usually unavailable in user mode)
    11 = break on data read or write (not instruction fetch)

  LEN field values:
    00 = 1-byte breakpoint
    01 = 2-byte breakpoint
    10 = 8-byte breakpoint (only on x64)
    11 = 4-byte breakpoint
```

### Dr6 — Debug Status Register

```
Dr6 bitfield (read after a debug exception):
  Bit 0 (B0) — DR0 condition met
  Bit 1 (B1) — DR1 condition met
  Bit 2 (B2) — DR2 condition met
  Bit 3 (B3) — DR3 condition met
  Bit 13 (BD) — debug register accessed (MOV DRx,reg detected if GD in DR7 was set)
  Bit 14 (BS) — single-step exception (TF flag in EFLAGS was set)
  Bit 15 (BT) — task switch exception (T flag in TSS, not relevant in user mode)
```

A `CONTEXT.Dr6` value of 0 after `GetThreadContext` means no debug exception has been recorded. Non-zero indicates which breakpoint fired.

---

## WinDbg: Inspecting CONTEXT During Exception Handling

### Setting and displaying a context record

```
; Set WinDbg to interpret the current context as a CONTEXT record
.cxr @$cxr

; Display all registers from that context
r

; Display a CONTEXT structure at a specific address (found on the stack)
dt ntdll!_CONTEXT 0x0012e4dc

; Read Eip directly from a CONTEXT at known offset
dd 0x0012e4dc+0xb8 L 1
0012f594  00401234   ← Eip value in CONTEXT
```

### Full WinDbg session: catching an access violation and inspecting CONTEXT

```
; --- Set a breakpoint at KiUserExceptionDispatcher to catch any exception ---
0:000> bp ntdll!KiUserExceptionDispatcher

; --- Trigger: run the program until it faults ---
0:000> g
Breakpoint 0 hit
ntdll!KiUserExceptionDispatcher:
77a71100 fc              cld

; --- At this point, ESP points to EXCEPTION_RECORD, then CONTEXT on stack ---
; The CONTEXT is at ESP+0x4+sizeof(EXCEPTION_RECORD) approximately
; But use .exr and .cxr to have WinDbg locate them properly

0:000> .exr -1
ExceptionAddress: 00401234 (target_app!bad_function+0x10)
   ExceptionCode: c0000005 (Access violation)
  ExceptionFlags: 00000000
ExceptionRecord: 00000000
ExceptionAddress: 00401234
NumberParameters: 2
   Parameter[0]: 00000000 (read access)
   Parameter[1]: 00000000 (invalid address)

0:000> .cxr -1
eax=00000001 ebx=00000000 ecx=7ffde000 edx=00401234 esi=0012ff70 edi=00000000
eip=00401234 esp=0012fe84 ebp=0012ff70 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246

; --- Show the CONTEXT structure fields manually ---
0:000> dt ntdll!_CONTEXT -r @esp
   +0x000 ContextFlags     : 0x1003f
   +0x004 Dr0              : 0
   +0x008 Dr1              : 0
   +0x00c Dr2              : 0
   +0x010 Dr3              : 0
   +0x014 Dr6              : 0
   +0x018 Dr7              : 0
   +0x08c SegGs            : 0
   +0x090 SegFs            : 0x3b
   +0x094 SegEs            : 0x23
   +0x098 SegDs            : 0x23
   +0x09c Edi              : 0
   +0x0a0 Esi              : 0x12ff70
   +0x0a4 Ebx              : 0
   +0x0a8 Edx              : 0x401234
   +0x0ac Ecx              : 0x7ffde000
   +0x0b0 Eax              : 1
   +0x0b4 Ebp              : 0x12ff70
   +0x0b8 Eip              : 0x401234   ← faulting instruction pointer
   +0x0bc SegCs            : 0x1b
   +0x0c0 EFlags           : 0x10246
   +0x0c4 Esp              : 0x12fe84   ← stack pointer at fault time
   +0x0c8 SegSs            : 0x23

; --- Patch Eip in CONTEXT to skip faulting instruction (2 bytes) ---
0:000> ed @esp+0xb8 0x401236   ; set Eip = 0x401234 + 2 = 0x401236
0:000> .cxr @esp                ; re-apply modified context
0:000> g                        ; continue execution from patched address

; --- Check for hardware breakpoints in a live session ---
0:000> r dr0
dr0=00000000   ← no hardware breakpoint on DR0
0:000> r dr7
dr7=00000000   ← debug control register empty: no BPs configured
```

### Finding the CONTEXT on the stack during SEH dispatch

```
; During SEH handler call, the handler receives parameters on its stack:
; [esp+0x04] = EXCEPTION_RECORD*
; [esp+0x08] = EstablisherFrame*
; [esp+0x0C] = CONTEXT*      ← pointer to the CONTEXT record
; [esp+0x10] = DispatcherContext*

0:000> dd esp L 5
0012f580  77a7113c 0012f698 0012ff30 0012f5a0 00000000
          ^retaddr  ^ExcRec   ^EstFrm   ^CONTEXT* ^DispCtx

; Read CONTEXT.Eip by dereferencing the pointer at [esp+0x0C]
0:000> dd poi(esp+0xc)+0xb8 L 1
0012f658  00401234   ← Eip from CONTEXT

; Modify CONTEXT.Eip in the handler (in the debugger, as if exploiting):
0:000> ed poi(esp+0xc)+0xb8 0xdeadbeef
; If handler returns ExceptionContinueExecution, execution resumes at 0xdeadbeef
```

---

## x64 CONTEXT Differences

On x64, the `CONTEXT` structure is significantly larger and uses different field names and offsets. The SEH model also changes fundamentally.

### Size: 0x4D0 bytes (1232 bytes)

### Key field offsets on x64

| Field | x64 Offset | Size | Notes |
|---|---|---|---|
| `ContextFlags` | +0x030 | 4 | Note: NOT at +0x000 on x64 |
| `MxCsr` | +0x034 | 4 | SSE control/status register |
| `SegCs` | +0x038 | 2 | |
| `SegDs` | +0x03A | 2 | |
| `SegEs` | +0x03C | 2 | |
| `SegFs` | +0x03E | 2 | |
| `SegGs` | +0x040 | 2 | |
| `SegSs` | +0x042 | 2 | |
| `EFlags` | +0x044 | 4 | |
| `Dr0` | +0x048 | 8 | |
| `Dr1` | +0x050 | 8 | |
| `Dr2` | +0x058 | 8 | |
| `Dr3` | +0x060 | 8 | |
| `Dr6` | +0x068 | 8 | |
| `Dr7` | +0x070 | 8 | |
| `Rax` | +0x078 | 8 | |
| `Rcx` | +0x080 | 8 | |
| `Rdx` | +0x088 | 8 | |
| `Rbx` | +0x090 | 8 | |
| `Rsp` | +0x098 | 8 | Stack pointer |
| `Rbp` | +0x0A0 | 8 | |
| `Rsi` | +0x0A8 | 8 | |
| `Rdi` | +0x0B0 | 8 | |
| `R8` | +0x0B8 | 8 | |
| `R9` | +0x0C0 | 8 | |
| `R10` | +0x0C8 | 8 | |
| `R11` | +0x0D0 | 8 | |
| `R12` | +0x0D8 | 8 | |
| `R13` | +0x0E0 | 8 | |
| `R14` | +0x0E8 | 8 | |
| `R15` | +0x0F0 | 8 | |
| `Rip` | +0x0F8 | 8 | Instruction pointer |
| `FltSave` (XSAVE_FORMAT) | +0x100 | 512 | SSE/AVX state |
| `XMM0` | +0x1A0 | 16 | SSE register 0 |
| `XMM1` | +0x1B0 | 16 | |
| `XMM2` | +0x1C0 | 16 | |
| `XMM3` | +0x1D0 | 16 | |
| `XMM4` | +0x1E0 | 16 | |
| `XMM5` | +0x1F0 | 16 | |
| `XMM6` | +0x200 | 16 | |
| `XMM7` | +0x210 | 16 | |
| `XMM8` | +0x220 | 16 | |
| `XMM9` | +0x230 | 16 | |
| `XMM10` | +0x240 | 16 | |
| `XMM11` | +0x250 | 16 | |
| `XMM12` | +0x260 | 16 | |
| `XMM13` | +0x270 | 16 | |
| `XMM14` | +0x280 | 16 | |
| `XMM15` | +0x290 | 16 | |
| Padding | +0x2A0 | 96 | Alignment to 0x300 |

### x64 SEH: no stack-based overflow to CONTEXT

On x64, Windows uses **table-based exception handling** (PDATA sections with `RUNTIME_FUNCTION` entries) instead of SEH frames on the stack. The exception dispatch process:
1. `RtlLookupFunctionEntry` finds the `RUNTIME_FUNCTION` for the faulting `Rip`
2. The unwind information is stored in the `.pdata` section of the executable image
3. There are no `EXCEPTION_REGISTRATION_RECORD` nodes on the stack to overwrite

This means the classic SEH overflow technique that redirects execution by overwriting `CONTEXT.Eip` does **not work on x64**. The `CONTEXT` is not adjacent to any attacker-controllable data on the user-mode stack in the same exploitable way.

`SetThreadContext` / thread hijacking still works on x64 — the `CONTEXT` API works the same. It is only the SEH overflow vector that is eliminated.

### x64 CONTEXT_ALL value

On x64, the architecture identifier in `ContextFlags` is `0x00100000` (not `0x00010000`):

```
CONTEXT_AMD64           = 0x00100000
CONTEXT_CONTROL         = 0x00100001  (Rsp, Rip, SegSs, SegCs, EFlags, Rbp)
CONTEXT_INTEGER         = 0x00100002  (Rax-Rdi, R8-R15)
CONTEXT_SEGMENTS        = 0x00100004  (SegDs, SegEs, SegFs, SegGs)
CONTEXT_FLOATING_POINT  = 0x00100008  (XMM/FP state)
CONTEXT_DEBUG_REGISTERS = 0x00100010  (Dr0-Dr7)
CONTEXT_FULL            = 0x00100007
CONTEXT_ALL             = 0x0010003F
```

---

## Common Mistakes

### 1. Confusing the saved stack pointer with the current stack pointer in the handler

```nasm
; WRONG interpretation:
; "CONTEXT.Esp is my current stack pointer in the handler"
; INCORRECT — CONTEXT.Esp is the stack pointer AT THE TIME THE EXCEPTION OCCURRED.
; The handler itself has its own stack frame with a different ESP.

; When a handler modifies CONTEXT.Esp, it is changing the stack pointer that will
; be restored when execution resumes via ExceptionContinueExecution.
; The current handler's stack is completely separate.
```

### 2. Assuming CONTEXT is at a fixed offset from ESP in the handler

The `CONTEXT*` is passed as a pointer parameter at `[esp+0x0C]` (the fourth parameter in the handler's stack frame). The actual `CONTEXT` structure is somewhere higher on the stack — its distance from the handler's `ESP` depends on how deep the call chain was when the exception occurred and how many frames the dispatcher set up. Always dereference the pointer:

```nasm
; WRONG: assuming CONTEXT is 0x200 bytes above current ESP
mov  ecx, esp
add  ecx, 0x200                  ; arbitrary — WRONG

; CORRECT: read the CONTEXT* parameter from the handler frame
mov  eax, dword [esp + 4]        ; EXCEPTION_POINTERS*
mov  ecx, dword [eax + 4]        ; CONTEXT* = ExcInfo->ContextRecord
; Now ECX points to the CONTEXT structure wherever it actually lives
```

### 3. Attempting CONTEXT.Rip modification via SEH overflow on x64

This is a common misconception when porting x86 exploits to x64. On x64:
- There are no `EXCEPTION_REGISTRATION_RECORD` nodes on the stack to overwrite
- Even if the `CONTEXT` record address could be determined, the stack is not organized in the same way that allows overflow-based corruption
- The proper x64 technique for redirecting execution is `SetThreadContext` on a suspended thread, not SEH overflow

### 4. Forgetting to set ContextFlags before GetThreadContext

```nasm
; WRONG: CONTEXT.ContextFlags is 0 (zero-filled buffer)
sub  esp, 0x2CC                  ; allocate CONTEXT
xor  eax, eax
; ... zero fill the buffer ...
; forgot to set ContextFlags!
push esp
push 0xFFFFFFFF
call [GetThreadContext]          ; returns success BUT fills no fields because ContextFlags=0
; Now all register fields are still zero — not the actual thread state

; CORRECT: set ContextFlags before calling
mov  dword [esp], 0x0001003F    ; ContextFlags = CONTEXT_ALL for x86
push esp
push 0xFFFFFFFF
call [GetThreadContext]
```

### 5. Using the same CONTEXT buffer for GetThreadContext and then SetThreadContext with modified Eip, but forgetting the ContextFlags still covers only what was read

If `GetThreadContext` was called with `CONTEXT_CONTROL` only (`0x00010001`), then `SetThreadContext` with the same `ContextFlags` will only update the control registers. If the intention is to also update integer registers, `ContextFlags` must be set to include `CONTEXT_INTEGER` before calling `SetThreadContext`.

### 6. Not accounting for CONTEXT alignment requirements on x64

On x64, the `CONTEXT` structure must be 16-byte aligned. If allocating on the stack with `sub rsp, 0x4D0`, the resulting address may not be 16-byte aligned depending on the stack state. Use `and rsp, -16` or `and rsp, 0xFFFFFFFFFFFFFFF0` to align before allocation.

---

## CONTEXT in Relation to Other Structures

### EXCEPTION_POINTERS

VEH handlers receive a pointer to this:

```
_EXCEPTION_POINTERS (x86):
  +0x00  ExceptionRecord  DWORD  pointer to _EXCEPTION_RECORD
  +0x04  ContextRecord    DWORD  pointer to _CONTEXT
```

### EXCEPTION_RECORD

Contains the exception code and faulting address:

```
_EXCEPTION_RECORD (x86):
  +0x00  ExceptionCode       DWORD   (e.g., 0xC0000005 = ACCESS_VIOLATION)
  +0x04  ExceptionFlags      DWORD
  +0x08  ExceptionRecord     DWORD   pointer to chained record, or NULL
  +0x0C  ExceptionAddress    DWORD   address of faulting instruction
  +0x10  NumberParameters    DWORD   number of ExceptionInformation elements
  +0x14  ExceptionInformation DWORD[15]
```

For `EXCEPTION_ACCESS_VIOLATION` (0xC0000005):
- `ExceptionInformation[0]` = 0 for read, 1 for write, 8 for DEP violation
- `ExceptionInformation[1]` = the address that was accessed (the invalid pointer value)

### EXCEPTION_REGISTRATION_RECORD (classic x86 SEH)

```
_EXCEPTION_REGISTRATION_RECORD (x86):
  +0x00  Next     DWORD  pointer to previous record (toward higher addresses), or 0xFFFFFFFF
  +0x04  Handler  DWORD  pointer to exception handler function
```

`FS:[0x00]` points to the innermost (most recently installed) registration record. Classic SEH chain overflow overwrites `Handler` at `+0x004`.

---

## Related Structures and APIs

- `TEB` — `FS:[0x00]` points to the SEH chain head; `TEB.NtTib.ExceptionList`; see `TEB.md`
- `PEB` — `PEB.NtGlobalFlag` can be used for debugger detection alongside CONTEXT-based checks
- `KTHREAD` — kernel-side thread structure that mirrors some CONTEXT fields; not accessible from user mode without a kernel exploit
- `RtlCaptureContext` — non-exception way to fill a CONTEXT with the calling thread's current state
- `NtContinue` — low-level version of `ZwContinue`; restores a CONTEXT to the CPU directly, used by exception dispatcher internals
- `NtGetContextThread` / `NtSetContextThread` — syscall equivalents of `GetThreadContext`/`SetThreadContext`; preferred in shellcode to avoid `kernel32.dll` dependency if `ntdll` is already resolved
