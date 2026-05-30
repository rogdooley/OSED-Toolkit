# TEB — Thread Environment Block (`_TEB`)

## Purpose

The Thread Environment Block is a per-thread data structure that the Windows kernel creates for every thread in a process. While the PEB (Process Environment Block) describes the process as a whole, the TEB describes the state of one specific thread. Every thread has its own TEB; they are all distinct allocations in the process's virtual address space.

The TEB holds: the thread's exception handler chain (SEH list), the thread's stack boundaries, a pointer to the shared PEB, thread-local storage (TLS) slots, the last Win32 error code, fiber information, the current locale, and dozens of other per-thread runtime values. The OS accesses the TEB constantly during thread execution — every `SetLastError`/`GetLastError` pair reads or writes TEB fields, and every exception dispatch starts by reading `TEB.ExceptionList`.

**Why per-thread vs. per-process:** The PEB holds data that is shared across all threads (the loaded module list, the process heap, the image base). The TEB holds data that must be private per-thread because threads execute concurrently. If the exception handler chain were in the PEB, one thread's SEH setup would overwrite another's. The TEB per-thread model solves this by giving each thread its own isolated copy of thread-specific runtime state.

**Where it lives in memory:** The TEB is allocated from the process's virtual address space at process startup (for the initial thread) or thread creation (for subsequent threads). On x86 Windows it is typically placed in the low 2 GB user-space region, often near the PEB. The kernel stores the TEB address in the thread's processor context at the segment register level — the `FS` segment's base address register in the GDT is set to the TEB address when the thread is scheduled onto a CPU.

---

## Why `FS` Points to the TEB (x86)

On x86 Windows, the `FS` segment register is **not** a general-purpose selector. The OS kernel, during thread creation, allocates a GDT (Global Descriptor Table) entry for the new thread's TEB. The GDT entry's base address is set to the TEB's virtual address. When the thread is scheduled onto a CPU core, the kernel loads this descriptor index into the `FS` selector register as part of the thread context switch. From that moment, any memory access of the form `FS:[offset]` is resolved by the CPU hardware as: (base address stored in FS descriptor) + offset = TEB_base + offset.

This is a hardware-enforced per-thread indirection — the CPU's segmentation unit automatically redirects `FS:`-prefixed accesses to the correct TEB without any explicit calculation. User-mode code never needs to know the TEB's actual address; it just uses `FS:`.

**Why `GS` on x64:** The x64 architecture retains segmentation in a limited form. `GS` replaces `FS` for the user-mode TEB pointer on x64. The `SWAPGS` instruction, which swaps the kernel-mode `GS` base (pointing to `KPCR`) with the user-mode saved base, is used during syscall/SYSRET transitions. In user mode, `GS` base = TEB address. The `GS:[0x30]` reads the TEB `Self` field; `GS:[0x60]` reads the PEB pointer.

---

## The `NT_TIB` Overlay

The first `0x1C` bytes of the TEB are shared with a structure called `NT_TIB` (Native Thread Information Block). `NT_TIB` is the public subset of the TEB that is accessible to user-mode programs via documented headers. The TEB begins with an `NT_TIB` embedded by value (not by pointer), so `TEB == NT_TIB` at offset 0.

```
_NT_TIB layout (x86):
  +0x000  ExceptionList      PEXCEPTION_REGISTRATION_RECORD  <- SEH chain head
  +0x004  StackBase          PVOID                           <- top of stack
  +0x008  StackLimit         PVOID                           <- guard page address
  +0x00C  SubSystemTib       PVOID                           <- subsystem specific
  +0x010  FiberData/Version  PVOID/ULONG                     <- fiber context or TLS version
  +0x014  ArbitraryUserPointer PVOID                         <- user-defined
  +0x018  Self               P_NT_TIB                        <- points back to NT_TIB/TEB
```

Because `NT_TIB` is embedded at offset 0 within `_TEB`, the TEB's `ExceptionList` field is also at TEB offset `0x000`, and `TEB.Self` is also at offset `0x018`. The `Self` field is a self-referential pointer: it stores the address of the TEB itself. This allows code to obtain the TEB address without relying on segment registers — you can read `FS:[0x18]` and get back the TEB's own virtual address, then use that address for non-segment-relative arithmetic.

---

## Exploit Relevance

The TEB is relevant to shellcode and exploit development in four key areas:

1. **PEB access:** `TEB.ProcessEnvironmentBlock` is the only reliable user-mode way to get the PEB address without a syscall. All PEB-walk shellcode goes through the TEB.

2. **SEH exploitation:** `TEB.ExceptionList` at offset `0x000` is the head of the Structured Exception Handling chain. SEH-based exploits overwrite handler records on the stack and may also interact with the chain head pointer in the TEB. Understanding TEB layout is essential to understanding how exception dispatch begins.

3. **Stack boundary checks:** `TEB.StackBase` and `TEB.StackLimit` bound the current thread's stack. Egghunter shellcode that scans memory by accessing arbitrary addresses needs to avoid the current stack or handle access violations gracefully — reading TEB to know stack bounds is one approach.

4. **Last error debugging:** During exploit development, when shellcode calls a Win32 API that fails, `TEB.LastErrorValue` holds the Win32 error code. Reading this without calling `GetLastError()` (which may itself fail or be hooked) is useful for diagnosing API failures in debugger sessions.

---

## Full Structure Layout

Offsets are from the start of the `_TEB`. On x86 Windows 10, the TEB size is approximately 0x1000 bytes (one page). On x64 it is larger. Only the most security-relevant fields are shown here.

| Field Name | Type | x86 Offset (hex/dec) | x64 Offset (hex/dec) | Purpose |
|---|---|---|---|---|
| `ExceptionList` | `*EXCEPTION_REGISTRATION_RECORD` | 0x000 / 0 | 0x000 / 0 | Head of SEH chain; first handler to consult on exception |
| `StackBase` | PVOID | 0x004 / 4 | 0x008 / 8 | High address (top) of the thread stack |
| `StackLimit` | PVOID | 0x008 / 8 | 0x010 / 16 | Low address (guard page) of the committed stack region |
| `SubSystemTib` | PVOID | 0x00C / 12 | 0x018 / 24 | Subsystem-specific TIB data; unused by Win32 subsystem |
| `FiberData` | PVOID | 0x010 / 16 | 0x020 / 32 | Pointer to fiber data when using fibers; else version info |
| `ArbitraryUserPointer` | PVOID | 0x014 / 20 | 0x028 / 40 | Free-use pointer for application code |
| `Self` | `*_NT_TIB` | 0x018 / 24 | 0x030 / 48 | Pointer to TEB itself; allows absolute address recovery |
| `EnvironmentPointer` | PVOID | 0x01C / 28 | 0x038 / 56 | Subsystem environment pointer; NULL for Win32 |
| `ClientId.UniqueProcess` | HANDLE | 0x020 / 32 | 0x040 / 64 | Process ID of owning process |
| `ClientId.UniqueThread` | HANDLE | 0x024 / 36 | 0x048 / 72 | Thread ID of this thread |
| `ActiveRpcHandle` | PVOID | 0x028 / 40 | 0x050 / 80 | Active RPC call handle |
| `ThreadLocalStoragePointer` | PVOID | 0x02C / 44 | 0x058 / 88 | Pointer to TLS slot array |
| `ProcessEnvironmentBlock` | `*_PEB` | 0x030 / 48 | 0x060 / 96 | Pointer to the process PEB |
| `LastErrorValue` | ULONG | 0x034 / 52 | 0x068 / 104 | Last Win32 error code (GetLastError result) |
| `CountOfOwnedCriticalSections` | ULONG | 0x038 / 56 | 0x06C / 108 | Number of CS owned by this thread |
| `CsrClientThread` | PVOID | 0x03C / 60 | 0x070 / 112 | CSR (Client-Server Runtime) client thread context |
| `Win32ThreadInfo` | PVOID | 0x040 / 64 | 0x078 / 120 | Pointer to kernel-mode win32k.sys thread info |
| `User32Reserved[26]` | ULONG[26] | 0x044 / 68 | 0x080 / 128 | Reserved for user32.dll internal use |
| `UserReserved[5]` | ULONG[5] | 0x0AC / 172 | 0x0E8 / 232 | Reserved for application use |
| `WOW32Reserved` | PVOID | 0x0C0 / 192 | 0x100 / 256 | Pointer to WOW32 thread state (x86 on x64) |
| `CurrentLocale` | ULONG | 0x0C4 / 196 | 0x108 / 264 | Thread LCID (locale identifier) |
| `FpSoftwareStatusRegister` | ULONG | 0x0C8 / 200 | 0x10C / 268 | FP emulation status (rarely used) |
| `ReservedForDebuggerInstrumentation[16]` | PVOID[16] | 0x0CC / 204 | 0x110 / 272 | Reserved for debugger hooks |
| `SystemReserved1[38]` | PVOID[38] | 0x10C / 268 | 0x1B8 / 440 | System reserved |
| `ExceptionCode` | LONG | 0x1A4 / 420 | 0x2C0 / 704 | Exception code for current exception |
| `ActivationContextStackPointer` | PVOID | 0x1A8 / 424 | 0x2C8 / 712 | Side-by-side activation context stack |
| `SpareBytes[24/8]` | UCHAR[] | varies | varies | Padding/spare bytes |
| `TxFsContext` | ULONG | 0x1D0 / 464 | 0x2E8 / 744 | Transaction FS context |
| `GdiTebBatch` | `GDI_TEB_BATCH` | 0x1D4 / 468 | 0x2F0 / 752 | GDI batch buffer (large, ~0x4E0 bytes) |
| `RealClientId.UniqueProcess` | HANDLE | 0x6B4 / 1716 | 0x7D8 / 2008 | Real (pre-impersonation) process ID |
| `RealClientId.UniqueThread` | HANDLE | 0x6B8 / 1720 | 0x7E0 / 2016 | Real thread ID |
| `GdiCachedProcessHandle` | PVOID | 0x6BC / 1724 | 0x7E8 / 2024 | Cached GDI process handle |
| `GdiClientPID` | ULONG | 0x6C0 / 1728 | 0x7F0 / 2040 | GDI client process ID |
| `GdiClientTID` | ULONG | 0x6C4 / 1732 | 0x7F4 / 2044 | GDI client thread ID |
| `GdiThreadLocalInfo` | PVOID | 0x6C8 / 1736 | 0x7F8 / 2048 | GDI thread local info pointer |
| `Win32ClientInfo[62]` | ULONG_PTR[62] | 0x6CC / 1740 | 0x800 / 2048 | Win32 client info (used by user32/win32k) |
| `glDispatchTable[233]` | PVOID[233] | 0x7C4 / 1988 | 0x9F0 / 2544 | OpenGL dispatch table |
| `glSectionInfo` | ULONG_PTR | 0xB74 / 2932 | 0x1138 / 4408 | OpenGL section info |
| `glSection` | PVOID | 0xB78 / 2936 | 0x1140 / 4416 | OpenGL section handle |
| `glTable` | PVOID | 0xB7C / 2940 | 0x1148 / 4424 | OpenGL table pointer |
| `glCurrentRC` | PVOID | 0xB80 / 2944 | 0x1150 / 4432 | Current OpenGL rendering context |
| `glContext` | PVOID | 0xB84 / 2948 | 0x1158 / 4440 | OpenGL context |
| `LastStatusValue` | ULONG | 0xBF4 / 3060 | 0x1250 / 4688 | Last NTSTATUS value (NtCurrentTeb()->LastStatusValue) |
| `StaticUnicodeString` | `UNICODE_STRING` | 0xBF8 / 3064 | 0x1258 / 4696 | Temporary Unicode string buffer |
| `StaticUnicodeBuffer[261]` | WCHAR[261] | 0xBFC / 3068 | 0x1260 / 4704 | Buffer for StaticUnicodeString |
| `DeallocationStack` | PVOID | 0xE0C / 3596 | 0x1478 / 5240 | Base address of stack allocation for deallocation |
| `TlsSlots[64]` | PVOID[64] | 0xE10 / 3600 | 0x1480 / 5248 | 64 inline TLS slots |
| `TlsLinks` | `LIST_ENTRY` | 0xF10 / 3856 | 0x1680 / 5760 | Links in TLS list |
| `Vdm` | PVOID | 0xF18 / 3864 | 0x1690 / 5776 | Virtual DOS Machine info |
| `ReservedForNtRpc` | PVOID | 0xF1C / 3868 | 0x1698 / 5784 | Reserved for NT RPC |
| `DbgSsReserved[2]` | PVOID[2] | 0xF20 / 3872 | 0x16A0 / 5792 | Debugger subsystem reserved |
| `HardErrorMode` | ULONG | 0xF28 / 3880 | 0x16B0 / 5808 | Hard error reporting mode |
| `Instrumentation[9/14]` | PVOID[] | 0xF2C / 3884 | 0x16B8 / 5816 | Reserved for instrumentation callbacks |
| `ActivityId` | `GUID` | 0xF50 / 3920 | 0x1720 / 5920 | ETW activity GUID |
| `SubProcessTag` | PVOID | 0xF60 / 3936 | 0x1730 / 5936 | Service tag identifier |
| `PerflibData` | PVOID | 0xF64 / 3940 | 0x1738 / 5944 | Performance library data |
| `EtwTraceData` | PVOID | 0xF68 / 3944 | 0x1740 / 5952 | ETW trace data |
| `WinSockData` | PVOID | 0xF6C / 3948 | 0x1748 / 5960 | WinSock per-thread data |
| `GdiBatchCount` | ULONG | 0xF70 / 3952 | 0x1750 / 5968 | Count of pending GDI batched calls |
| `IdealProcessorValue` | ULONG | 0xF74 / 3956 | 0x1754 / 5972 | Ideal processor affinity value |
| `GuaranteedStackBytes` | ULONG | 0xF78 / 3960 | 0x1758 / 5976 | Guaranteed remaining stack space |
| `TlsExpansionSlots` | PVOID* | 0xF80 / 3968 | 0x1780 / 6016 | Pointer to expanded TLS slots array |

---

## Deep Field Explanations

### `ExceptionList` (+0x000)

This is the most important field in the TEB for SEH (Structured Exception Handling) exploitation. It is a pointer to an `EXCEPTION_REGISTRATION_RECORD` structure — specifically the first record in a singly-linked list of exception handlers registered by the current thread.

**Why it is at offset 0x000:** The designers of Windows NT placed `ExceptionList` at the very beginning of the TEB (which is also the beginning of `NT_TIB`) deliberately. Because `FS` always points to the TEB, and the TEB starts with the exception list head, `FS:[0x00]` always gives the current exception handler head for any thread — no arithmetic is needed. This is performance-critical: exception dispatch must be fast, and avoiding pointer dereferences keeps cache lines warm.

**Structure of `EXCEPTION_REGISTRATION_RECORD`:**

```
_EXCEPTION_REGISTRATION_RECORD (x86):
  +0x000  Next     PEXCEPTION_REGISTRATION_RECORD  <- next record, or 0xFFFFFFFF if last
  +0x004  Handler  PEXCEPTION_ROUTINE              <- pointer to handler function
```

The list is terminated by a record whose `Next` field is `0xFFFFFFFF` (cast to a pointer, this is `-1` or `0xFFFFFFFF` on x86). The kernel's default last-resort handler is always at the end.

**How exception dispatch uses it:** When an exception occurs, `ntdll!KiUserExceptionDispatcher` is called by the kernel. It begins by reading `FS:[0x00]` to get the head of the chain, then walks each record calling `Handler(ExceptionRecord, EstablisherFrame, Context, Dispatcher)` until one returns `ExceptionContinueExecution` or `ExceptionContinueSearch`. The SEH exploitation technique overwrites a `Handler` pointer on the stack (through a buffer overflow) so that when the exception fires, the attacker-controlled handler address is called.

**SEH chain head manipulation:** Because `ExceptionList` is at TEB offset `0x000`, direct overwrites of TEB memory (rare but possible via kernel exploit) can redirect the entire exception chain.

### `StackBase` (+0x004 x86 / +0x008 x64) and `StackLimit` (+0x008 x86 / +0x010 x64)

`StackBase` stores the **highest** virtual address of the thread's stack (the initial value of the stack pointer when the thread started). On x86, stacks grow downward, so `StackBase` is the top — the address just past the last valid stack byte. `StackLimit` stores the **lowest** currently-committed address in the stack region — not the absolute bottom of the reserved region, but the current guard page address.

**Why "limit" is the low address:** Microsoft's naming convention here is architectural: `StackLimit` is the limit in the sense of the boundary below which the stack cannot currently grow without triggering a guard page fault (which causes the kernel to commit more pages and update `StackLimit`). The total reserved stack region extends below `StackLimit`, but pages below it are not yet committed.

**Egghunter use:** An egghunter payload that searches memory for a specific tag cannot read arbitrary addresses without generating access violations. One approach is to constrain the search to the current thread's stack region, which is guaranteed readable, using `StackBase` and `StackLimit`:

```asm
; Check if an address is within the current thread's stack
mov   eax, fs:[4]       ; EAX = StackBase (highest address, top)
mov   ecx, fs:[8]       ; ECX = StackLimit (lowest committed, bottom)
; target address in EDX
cmp   edx, ecx          ; below StackLimit? (< lowest valid)
jb    not_on_stack
cmp   edx, eax          ; above StackBase? (> top)
ja    not_on_stack
; address is within current stack range
```

### `Self` (+0x018 x86 / +0x030 x64)

The `Self` field contains a pointer to the TEB structure itself. This is a self-referential pointer: if the TEB is located at virtual address `0x7FFDF000`, then `TEB.Self` contains the value `0x7FFDF000`.

**Why this field exists:** When code has an `FS`-relative way to access TEB fields, it does not need `Self` — it just uses `FS:[offset]`. But when code obtains the TEB address by some other means (e.g., from a kernel callback, from RPC, or from an injected thread that has set up its own TEB-like structure), it can read `Self` to confirm or retrieve the canonical TEB pointer. The `Self` field also allows code to obtain the TEB's base address as an absolute pointer, enabling pointer arithmetic on TEB fields without segment-register syntax:

```asm
; Get TEB base address as an absolute pointer (x86)
mov   eax, fs:[18h]     ; EAX = TEB.Self = absolute TEB address
; Now EAX holds the TEB base as a regular pointer
mov   ecx, [eax+30h]    ; ECX = TEB.ProcessEnvironmentBlock = PEB address
                        ; Equivalent to: mov ecx, fs:[30h]
                        ; but now EAX can be stored, passed to functions, etc.
```

### `ProcessEnvironmentBlock` (+0x030 x86 / +0x060 x64)

This field stores a pointer to the process's PEB. All threads in the process share the same PEB, so this field has the same value in every thread's TEB. It is the canonical user-mode path to the PEB.

**Why the offset changed from 0x030 (x86) to 0x060 (x64):**

From offset 0x018 (`Self`) onward, the TEB layout has been modified for x64 to accommodate 8-byte pointers. Let us trace the accumulation of offsets between `Self` (+0x018 on x86) and `ProcessEnvironmentBlock` (+0x030 on x86):

- `Self` ends at +0x018 + 4 = +0x01C on x86.
- Next is `EnvironmentPointer` (PVOID): +0x01C, 4 bytes → ends at +0x020.
- `ClientId` (two HANDLEs): +0x020, 8 bytes → ends at +0x028.
- `ActiveRpcHandle` (PVOID): +0x028, 4 bytes → ends at +0x02C.
- `ThreadLocalStoragePointer` (PVOID): +0x02C, 4 bytes → ends at +0x030.
- `ProcessEnvironmentBlock` at +0x030.

On x64, all PVOID/HANDLE fields double to 8 bytes:
- `Self` at +0x030 (x64), 8 bytes → +0x038.
- `EnvironmentPointer`: +0x038, 8 bytes → +0x040.
- `ClientId.UniqueProcess`: +0x040, 8 bytes → +0x048.
- `ClientId.UniqueThread`: +0x048, 8 bytes → +0x050.
- `ActiveRpcHandle`: +0x050, 8 bytes → +0x058.
- `ThreadLocalStoragePointer`: +0x058, 8 bytes → +0x060.
- `ProcessEnvironmentBlock` at +0x060.

Each pointer doubling from 4 to 8 bytes accumulates 4 additional bytes. There are 6 pointer-sized fields between `Self` and `ProcessEnvironmentBlock`, contributing 6 × 4 = 24 additional bytes, which is exactly `0x060 - 0x030 = 0x030` on x64 vs. x86.

### `LastErrorValue` (+0x034 x86 / +0x068 x64)

This ULONG stores the last Win32 error code set by an API call in the current thread. `SetLastError(code)` simply writes `code` to `TEB.LastErrorValue`. `GetLastError()` simply reads it. The field is per-thread to avoid race conditions — each thread has its own last error that is not visible to other threads.

**Why exploit developers care:** During shellcode debugging, when an API call returns 0 (failure), reading `TEB.LastErrorValue` directly in WinDbg (`dd @$teb+0x34 L1` on x86) avoids the overhead of a `GetLastError()` call and works even when the target process is in a state where calling functions is unreliable. It is also useful for verifying that a hooked `GetLastError` is not lying to you — compare the direct TEB read against the API return.

---

## x86 vs x64 Differences

### Segment Register

x86 uses `FS`; x64 uses `GS`. This is the most visible difference and affects all TEB-relative assembly.

### Offset Differences

All pointer-sized fields shift on x64 due to 8-byte pointer width. The most commonly used offsets:

| Field | x86 | x64 |
|---|---|---|
| `ExceptionList` | 0x000 | 0x000 |
| `StackBase` | 0x004 | 0x008 |
| `StackLimit` | 0x008 | 0x010 |
| `Self` | 0x018 | 0x030 |
| `ProcessEnvironmentBlock` | 0x030 | 0x060 |
| `LastErrorValue` | 0x034 | 0x068 |

### SEH on x64

On x64 Windows, stack-based SEH (the linked list of `EXCEPTION_REGISTRATION_RECORD` structures on the stack) **does not exist**. x64 exception handling uses table-based unwinding: the PE header's `.pdata` section contains `RUNTIME_FUNCTION` entries describing function stack frame layouts and exception handler addresses. There are no `EXCEPTION_REGISTRATION_RECORD` nodes pushed onto the stack during x64 execution.

As a consequence, `TEB.ExceptionList` is not actively used in normal x64 code paths. The value at `GS:[0x00]` on x64 may be `0xFFFFFFFFFFFFFFFF` (the terminal sentinel) permanently. SEH exploitation techniques (overwiting handler pointers on the stack) do not apply to x64 native code. This is one of the fundamental reasons why x64 exploitation is harder than x86 exploitation.

### WOW64 TEB Layout

A 32-bit process running under WOW64 has both a 32-bit TEB and a 64-bit TEB. The 32-bit TEB is accessible via `FS` in 32-bit code. The 64-bit TEB's address is stored in the 32-bit TEB's `GdiBatchCount` field (repurposed), but this is an implementation detail that varies by Windows version. Standard 32-bit shellcode operates on the 32-bit TEB and PEB exclusively.

---

## WinDbg Verification

### Locate the TEB

```
0:000> !teb
TEB at 0012f000
    ExceptionList:        0012fca8
    StackBase:            00130000
    StackLimit:           0012d000
    SubSystemTib:         00000000
    FiberData:            00001e00
    ArbitraryUserPointer: 00000000
    Self:                 0012f000    <-- same as TEB address
    EnvironmentPointer:   00000000
    ClientId:             00000d4c . 00000d50
    RpcHandle:            00000000
    Tls Storage:          00000000
    PEB Address:          0064f000
    LastErrorValue:       00000000
    LastStatusValue:      c0000034
    Count Owned Locks:    0
    HardErrorMode:        0
```

**What to observe:** `Self` matches `TEB at 0012f000`. `PEB Address` can be confirmed against `!peb`. `ExceptionList` points to the top SEH frame on the stack, which you can dump with `dt ntdll!_EXCEPTION_REGISTRATION_RECORD 0012fca8`.

### Dump the Raw TEB Structure

```
0:000> dt ntdll!_TEB @$teb
   +0x000 NtTib            : _NT_TIB
   +0x000 ExceptionList    : 0x0012fca8 _EXCEPTION_REGISTRATION_RECORD
   +0x004 StackBase        : 0x00130000 Void
   +0x008 StackLimit       : 0x0012d000 Void
   +0x00c SubSystemTib     : (null)
   +0x010 FiberData        : 0x00001e00 Void
   +0x014 ArbitraryUserPointer : (null)
   +0x018 Self             : 0x0012f000 _NT_TIB
   ...
   +0x030 ProcessEnvironmentBlock : 0x0064f000 _PEB
   +0x034 LastErrorValue   : 0
```

### Walk the SEH Chain

```
0:000> dt ntdll!_EXCEPTION_REGISTRATION_RECORD 0x0012fca8
   +0x000 Next    : 0x0012fd10 _EXCEPTION_REGISTRATION_RECORD
   +0x004 Handler : 0x77c50000     ntdll!_except_handler4

0:000> dt ntdll!_EXCEPTION_REGISTRATION_RECORD 0x0012fd10
   +0x000 Next    : 0xffffffff _EXCEPTION_REGISTRATION_RECORD
   +0x004 Handler : 0x77c3e400     ntdll!FinalExceptionHandlerPad4
```

**Reading this:** The chain has two nodes. The first has a real handler (`_except_handler4`). The second has `Next = 0xFFFFFFFF`, which is the sentinel marking the end of the chain. Its handler is `FinalExceptionHandlerPad4`, the OS default last-resort handler that terminates the process if no prior handler claimed the exception.

### Verify Key Offsets

```
0:000> ? @@c++(((ntdll!_TEB *)@$teb)->ProcessEnvironmentBlock)
Evaluate expression: 6647808 = 0064f000

0:000> dd @$teb+0x30 L1
0012f030  0064f000    ; Confirm PEB pointer at +0x30
```

### Check Thread Stack Bounds

```
0:000> dd @$teb+4 L2
0012f004  00130000 0012d000    ; StackBase=0x130000, StackLimit=0x12d000
0:000> ? 130000 - 12d000
Evaluate expression: 12288 = 0x3000   ; 12 KB of committed stack space currently
```

---

## Assembly Walkthrough

### Accessing TEB Fields Efficiently

```asm
; ─── x86 TEB Field Access Examples ──────────────────────────────────────────
;
; Three ways to get the PEB — illustrating the FS:[0x18] Self technique

; Method 1: Direct segment-relative access (most compact)
mov   eax, fs:[30h]     ; EAX = PEB pointer
                        ; FS base = TEB, +0x30 = ProcessEnvironmentBlock

; Method 2: Via Self pointer (useful when you need TEB address for other work)
mov   edx, fs:[18h]     ; EDX = TEB.Self = absolute TEB base address
mov   eax, [edx+30h]    ; EAX = TEB.ProcessEnvironmentBlock = PEB pointer
                        ; This is equivalent to Method 1, but EDX now holds
                        ; TEB address usable for further TEB field access

; Method 3: Explicit TEB address arithmetic (useful in shellcode frameworks)
; Obtain TEB from EXCEPTION_REGISTRATION_RECORD context:
; (The ERR has a pointer to the CONTEXT and establisher frame, but not TEB directly)
; Usually Method 1 is preferred unless segment registers are being manipulated

; ─── Get stack bounds (x86) ──────────────────────────────────────────────────
read_stack_bounds:
    mov   eax, fs:[4]           ; EAX = StackBase (top of stack, highest address)
    mov   ecx, fs:[8]           ; ECX = StackLimit (committed bottom, lowest address)
    ; Stack valid range: ECX (inclusive) to EAX (exclusive)
    ; Stack currently grows toward ECX; guard page lives just below ECX

; ─── Read last error without calling GetLastError ────────────────────────────
read_last_error:
    mov   eax, fs:[34h]         ; EAX = TEB.LastErrorValue
    ; No API call needed; direct TEB access is not hookable by user-mode hooks
    ; Useful for diagnosing API failures in shellcode without call overhead
```

### SEH Frame Setup (x86 Only — Does Not Apply to x64 Native)

This is how the compiler-generated `__try/__except` blocks push SEH frames:

```asm
; ─── Manual SEH frame push (x86) ─────────────────────────────────────────────
;
; This is what compiler-generated SEH does, shown explicitly.
; After this, the frame is at the top of TEB.ExceptionList.
;
; Assume: handler_routine address known, ECX = 0

push  offset handler_routine    ; push handler address
push  fs:[ecx]                  ; push old ExceptionList head (fs:[0] = ExceptionList)
mov   fs:[ecx], esp             ; set ExceptionList head to point at our new record
                                ; ESP now points at:
                                ;   [ESP+0x00] = Next (old ExceptionList value)
                                ;   [ESP+0x04] = Handler (handler_routine address)
                                ; This is exactly EXCEPTION_REGISTRATION_RECORD layout

; ... protected code here ...

; Teardown (must execute even on exception path via handler):
pop   dword ptr fs:[ecx]        ; restore old ExceptionList head (pops into FS:[0])
add   esp, 4                    ; discard the handler pointer we pushed
```

---

## Common Mistakes

### Mistake 1: Using `FS:[0x30]` on x64

The single most common porting error when converting x86 shellcode to x64 is forgetting that `FS:[0x30]` does not give the PEB on x64 — it may give 0 or an access violation. On x64, you must use `GS:[0x60]` for the PEB and `GS:[0x30]` for the TEB `Self` pointer. Mixed-mode code (32-bit shellcode running in WOW64) still uses `FS:[0x30]` — only pure 64-bit shellcode needs `GS`.

### Mistake 2: Assuming SEH Chain Terminator is 0x00000000

The SEH chain in the TEB terminates with `Next = 0xFFFFFFFF` (all bits set, -1 as a signed 32-bit integer). Shellcode that walks the SEH chain and stops when `Next == NULL` will walk off the end of the valid chain into whatever memory follows the last record. Always test for `Next == 0xFFFFFFFF`:

```asm
walk_seh:
    mov   eax, fs:[0]       ; EAX = current ExceptionList head
.loop:
    cmp   eax, 0xFFFFFFFF   ; sentinel value for end of SEH chain
    je    .done             ; reached end
    mov   eax, [eax]        ; EAX = Next (advance one node)
    jmp   .loop
.done:
```

### Mistake 3: `StackLimit` is Not the Stack Reserve Bottom

`TEB.StackLimit` is the bottom of the currently **committed** stack region, not the bottom of the **reserved** region. Windows reserves more virtual address space than it commits for thread stacks (the default reserve is 1 MB, default commit is one page). The guard page lives at `StackLimit - PAGE_SIZE`, and touching the guard page triggers a `STATUS_GUARD_PAGE_VIOLATION` that causes the kernel to commit another page and update `StackLimit`. Egghunters that rely on `StackLimit` to set a search lower bound may miss memory if the stack has not grown to its minimum committed size yet.

### Mistake 4: Thread-Local Storage Pointer is NULL Until Used

`TEB.ThreadLocalStoragePointer` at +0x02C (x86) is NULL until the first TLS slot is allocated and set for this thread. Shellcode or injected code accessing this field as if it is always valid will crash in threads that have never used TLS. Always check for NULL before dereferencing.

### Mistake 5: `ExceptionList` on x64 Is Not Maintained

On x64 Windows, `TEB.ExceptionList` (at GS:[0x00]) is set to `0xFFFFFFFFFFFFFFFF` and is never modified during normal execution. The x64 runtime does not push/pop SEH nodes onto the stack. Reading `GS:[0x00]` on x64 expecting to find a valid exception handler chain will return the sentinel value or garbage. All x64 exception handling is via `RUNTIME_FUNCTION` tables in the PE image's `.pdata` section.

---

## Defensive Caveats

**What EDR products monitor:**

1. **`FS:[0x30]` access pattern:** The instruction sequence `mov reg, fs:[0x30]` followed by dereferences characteristic of PEB walking is a primary shellcode detection signature. Solutions that monitor instruction-level behavior (Intel PT tracing, ETW with kernel tracing enabled) flag this. Obfuscation techniques include reading `FS:[0x18]` first (TEB `Self`) and computing the PEB offset indirectly, or using `NtCurrentTeb()` (a function call rather than an inline FS-relative read).

2. **SEH frame manipulation:** On x86, pushing a crafted exception handler record and writing to `FS:[0x00]` is a classic shellcode behavior. Modern DEP/NX enforcement means that unless the handler address points to executable memory, the dispatch will fault again. SafeSEH (a linker feature that whitelist-validates SEH handler addresses) and SEHOP (SEH Overwrite Protection — a runtime check that validates the SEH chain terminates at a known location) both detect and block classic SEH overwrite exploits.

3. **`LastErrorValue` as canary:** Some detection logic monitors anomalous `LastErrorValue` sequences — for example, a process making dozens of API calls that all return error code 5 (ACCESS_DENIED) in rapid succession may be a brute-force privilege escalation attempt.

4. **TEB integrity monitoring:** Kernel-mode security products can register `PsSetCreateThreadNotifyRoutine` callbacks and read the TEB of newly created threads for suspicious indicators (e.g., `ExceptionList` pointing outside the stack region, which would indicate a pre-placed fake SEH frame).

**For red team practice:** Understanding the TEB is foundational to understanding why SEH exploits worked on pre-Vista systems and why the mitigations (SafeSEH, SEHOP, x64 table-based handling) were effective. When analyzing a target for exploitability, determine which mitigations are enabled — a 32-bit application without `/SafeSEH` running on x86 Windows is fundamentally different from the same app with SEHOP enabled.
