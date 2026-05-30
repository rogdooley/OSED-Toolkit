# Kernel32 Location Techniques

## Purpose

This document covers the full range of techniques used in Windows shellcode to locate kernel32.dll in the process address space. Kernel32 is the primary target because it exports `LoadLibraryA` and `GetProcAddress`, which together unlock the entire Windows API surface. Finding kernel32 is the critical first step; without it, shellcode cannot call any other function.

## Exploit Relevance

Every non-trivial Windows shellcode must locate at least one known DLL to bootstrap API resolution. The choice to target kernel32 specifically is because:

1. It is always loaded in every Windows process (even svchost, notepad, and injected shellcode targets).
2. It exports `LoadLibraryA` — the universal key to loading any other DLL.
3. It exports `GetProcAddress` — allowing lookup of any API by name string.
4. It exports `VirtualAlloc`, `CreateThread`, `WinExec`, and other primitives directly useful to shellcode.

KernelBase.dll (introduced in Windows 8) actually implements many of these APIs, with kernel32 forwarding to it. However, resolving through kernel32 still works because the forwarder chain is handled transparently or can be followed explicitly.

---

## Structure Prerequisites

All techniques below depend on understanding the following Windows structures. Key offsets are repeated here for reference.

```
TEB (Thread Environment Block):
  x86: FS segment base
  x64: GS segment base
  x86 offset 0x30 = PEB pointer
  x64 offset 0x60 = PEB pointer

PEB (Process Environment Block):
  x86 offset 0x0c = Ldr (PEB_LDR_DATA*)
  x64 offset 0x18 = Ldr

PEB_LDR_DATA:
  x86 offset 0x0c = InLoadOrderModuleList.Flink
  x86 offset 0x1c = InInitializationOrderModuleList.Flink

LDR_DATA_TABLE_ENTRY (offsets from InLoadOrderLinks base = entry start):
  x86 offset 0x18 = DllBase
  x86 offset 0x2c = BaseDllName (UNICODE_STRING)
  x86 offset 0x2c = BaseDllName.Length (USHORT)
  x86 offset 0x30 = BaseDllName.Buffer (PWSTR)

LDR_DATA_TABLE_ENTRY (offsets from InInitializationOrderLinks):
  x86 +0x08 = DllBase
  x86 +0x1c = BaseDllName.Length (USHORT)
  x86 +0x20 = BaseDllName.Buffer (PWSTR)
```

---

## Technique 1: PEB Walk via InInitializationOrderModuleList

### Overview

The classic technique. Walk the initialization order list from PEB_LDR_DATA, comparing BaseDllName at each entry. On Windows XP through 7, kernel32 is reliably the second entry (after ntdll), so some implementations skip name comparison entirely. On modern Windows, name comparison is mandatory.

### Reliability by Windows Version

| Version | ntdll position | kernel32 position | Notes |
|---|---|---|---|
| Windows XP (all SP) | 0 | 1 | Classic skip-1 works |
| Windows Vista | 0 | 1 | Generally works |
| Windows 7 | 0 | 1 | Generally works |
| Windows 8 / 8.1 | 0 | varies | KernelBase inserted; skip-N breaks |
| Windows 10 (1507-21H2) | 0 | varies | Additional early-init modules |
| Windows 11 | 0 | varies | Do not rely on position |

### Assembly Implementation

```asm
; ============================================================
; find_kernel32_initorder
; Uses InInitializationOrderModuleList
; Returns: EAX = kernel32.dll base address
; Clobbers: EAX, ECX, ESI, EDI
; ============================================================

find_kernel32_initorder:
    ; Step 1: Get PEB via FS segment
    xor     eax, eax                ; zero EAX for clean encoding
    mov     eax, fs:[eax + 0x30]    ; EAX = PEB base address

    ; Step 2: Get PEB.Ldr
    mov     eax, [eax + 0x0c]       ; EAX = PEB_LDR_DATA*

    ; Step 3: First entry in InInitializationOrderModuleList
    ; PEB_LDR_DATA + 0x1c = InInitializationOrderModuleList.Flink
    mov     esi, [eax + 0x1c]       ; ESI = first InInitOrderLinks ptr

    ; Save list head for termination detection
    lea     ecx, [eax + 0x1c]       ; ECX = list head address

.initorder_loop:
    ; Termination: Flink == list head
    cmp     esi, ecx
    je      .initorder_fail

    ; BaseDllName.Length at InInitOrderLinks + 0x1c
    movzx   edx, word [esi + 0x1c]  ; EDX = BaseDllName.Length (bytes)

    ; kernel32.dll = 12 chars * 2 = 24 = 0x18 bytes
    cmp     edx, 0x18
    jne     .initorder_next

    ; BaseDllName.Buffer at InInitOrderLinks + 0x20
    mov     edi, [esi + 0x20]       ; EDI = wide string pointer

    ; Compare "KERNEL32.DLL" (unicode, uppercase)
    ; 'K' = 0x004B, 'E' = 0x0045 => DWORD at [0] = 0x0045004B
    mov     eax, [edi]
    cmp     eax, 0x0045004B         ; "KE"
    jne     .initorder_next

    mov     eax, [edi + 0x04]
    cmp     eax, 0x004E0052         ; "RN"
    jne     .initorder_next

    mov     eax, [edi + 0x08]
    cmp     eax, 0x004C0045         ; "EL"
    jne     .initorder_next

    mov     eax, [edi + 0x0c]
    cmp     eax, 0x00320033         ; "32"
    jne     .initorder_next

    mov     eax, [edi + 0x10]
    cmp     eax, 0x0044002E         ; ".D"
    jne     .initorder_next

    mov     eax, [edi + 0x14]
    cmp     eax, 0x004C004C         ; "LL"
    jne     .initorder_next

    ; Match: DllBase at InInitOrderLinks + 0x08
    mov     eax, [esi + 0x08]
    ret

.initorder_next:
    mov     esi, [esi]              ; follow Flink
    jmp     .initorder_loop

.initorder_fail:
    xor     eax, eax
    ret
```

---

## Technique 2: PEB Walk via InLoadOrderModuleList (Recommended)

### Overview

Walking InLoadOrderModuleList is the more robust approach. The `Flink` from this list points directly to the start of `LDR_DATA_TABLE_ENTRY` (since InLoadOrderLinks is at offset 0x00), making the offset arithmetic simpler and less error-prone. Name comparison is always performed, making this version reliable across all Windows versions.

### Key Offset Advantage

Because InLoadOrderLinks is at offset 0x00 in LDR_DATA_TABLE_ENTRY, following Flink gives you the entry start directly:

```
[Flink + 0x00]  = InLoadOrderLinks (the LIST_ENTRY itself)
[Flink + 0x18]  = DllBase
[Flink + 0x2c]  = BaseDllName (UNICODE_STRING)
[Flink + 0x2c]  = BaseDllName.Length (USHORT)
[Flink + 0x2e]  = BaseDllName.MaximumLength (USHORT)
[Flink + 0x30]  = BaseDllName.Buffer (PWSTR)
```

### Case Sensitivity Handling

Windows stores the module name as "KERNEL32.DLL" (all uppercase). However, to write defensive code, we can normalize to lowercase for comparison using a bitwise OR trick:

For ASCII letters, bit 5 (value 0x20) being set means lowercase. Setting it with OR converts uppercase to lowercase. Non-alpha characters (digits, periods) either already have bit 5 set or are unaffected for the purpose of our comparisons.

### Assembly Implementation

```asm
; ============================================================
; find_kernel32_loadorder — robust, recommended technique
; Uses InLoadOrderModuleList with case-insensitive compare
; Returns: EAX = kernel32.dll base address, 0 on failure
; Clobbers: EAX, EBX, ECX, ESI, EDI
; ============================================================

find_kernel32_loadorder:
    ; Get PEB
    xor     eax, eax
    mov     eax, fs:[eax + 0x30]    ; EAX = PEB

    ; Get PEB_LDR_DATA
    mov     eax, [eax + 0x0c]       ; EAX = PEB_LDR_DATA*

    ; InLoadOrderModuleList head is at PEB_LDR_DATA + 0x0c
    lea     ebx, [eax + 0x0c]       ; EBX = list head address (for termination)
    mov     esi, [eax + 0x0c]       ; ESI = first Flink = first LDR entry start

.load_loop:
    ; Check for list wrap-around (end of list)
    cmp     esi, ebx
    je      .load_fail

    ; Get BaseDllName.Length (at LDR entry + 0x2c)
    movzx   ecx, word [esi + 0x2c]

    ; Match kernel32.dll length: 12 wide chars = 24 bytes = 0x18
    cmp     ecx, 0x18
    jne     .load_next

    ; Load BaseDllName.Buffer pointer
    mov     edi, [esi + 0x30]       ; EDI = wide string

    ; Case-insensitive compare using OR 0x20 on alphabetic chars
    ; For Unicode: each char is 2 bytes; high byte is 0x00 for basic latin
    ; OR 0x00200020 sets bit 5 of both low bytes in a DWORD
    mov     eax, [edi + 0x00]
    or      eax, 0x00200020         ; lowercase both chars
    cmp     eax, 0x0065006B         ; "ke" in lowercase unicode
    jne     .load_next

    mov     eax, [edi + 0x04]
    or      eax, 0x00200020
    cmp     eax, 0x006E0072         ; "rn"
    jne     .load_next

    mov     eax, [edi + 0x08]
    or      eax, 0x00200020
    cmp     eax, 0x006C0065         ; "el"
    jne     .load_next

    mov     eax, [edi + 0x0c]
    ; digits '3','2' are not affected meaningfully by OR 0x20
    ; '3' = 0x33, OR 0x20 = 0x33 (unchanged); same for '2'
    cmp     eax, 0x00320033         ; "32"
    jne     .load_next

    mov     eax, [edi + 0x10]
    ; '.' = 0x2E, OR 0x20 = 0x2E; 'D' = 0x44, OR 0x20 = 0x64 ('d')
    or      eax, 0x00200000         ; only OR high char position
    cmp     eax, 0x0064002E         ; ".d"
    jne     .load_next

    mov     eax, [edi + 0x14]
    or      eax, 0x00200020
    cmp     eax, 0x006C006C         ; "ll"
    jne     .load_next

    ; Found it — DllBase at LDR entry + 0x18
    mov     eax, [esi + 0x18]
    ret

.load_next:
    mov     esi, [esi]              ; follow Flink (InLoadOrderLinks.Flink = next entry)
    jmp     .load_loop

.load_fail:
    xor     eax, eax
    ret
```

---

## Technique 3: SEH-Based Location

### Overview

Every thread's exception handler list is stored in the TEB at `fs:[0x00]` (the ExceptionList). When a Win32 thread starts, kernel32 registers exception handlers as part of `BaseThreadInitThunk`. These handlers are registered within kernel32's text section. By walking the SEH chain and finding a handler address that points into a loaded PE image, we can identify and verify kernel32.

### Algorithm

1. Read `fs:[0x00]` — the head of the SEH chain (pointer to `EXCEPTION_REGISTRATION_RECORD`).
2. Each `EXCEPTION_REGISTRATION_RECORD` contains:
   - `Next` (offset 0x00): pointer to the next record
   - `Handler` (offset 0x04): pointer to the exception handler function
3. For each `Handler` address, align down to a 0x1000 or 0x10000 (64 KB) page boundary.
4. Scan backward in 0x1000 increments for an "MZ" header (0x5A4D).
5. Once found, verify it is a valid PE and compare the module name.

### Why This Is Fragile

- Not all SEH handlers in the chain are registered by kernel32. Application code, CRT, and other DLLs register handlers. The first SEH entry might point into the CRT or an application DLL.
- On modern Windows with CFG (Control Flow Guard) and strict SEH validation, walking the SEH chain may not behave as expected.
- 64-bit Windows does not use FS-based SEH chains; it uses table-based exception handling (SAFESEH).

### Code Example

```asm
; ============================================================
; find_kernel32_seh - SEH chain walk approach
; Unreliable on modern Windows — included for completeness
; Returns: EAX = kernel32.dll base address (best guess), 0 on fail
; Clobbers: EAX, EBX, ECX, ESI
; ============================================================

find_kernel32_seh:
    ; Read ExceptionList head from TEB
    mov     esi, fs:[0x00]          ; ESI = EXCEPTION_REGISTRATION_RECORD*

.seh_walk:
    ; Check for end of chain (0xFFFFFFFF = no more entries)
    cmp     esi, 0xFFFFFFFF
    je      .seh_fail
    test    esi, esi
    jz      .seh_fail

    ; Get the handler address
    mov     ebx, [esi + 0x04]       ; EBX = Handler function pointer

    ; Align down to 64KB page boundary to find potential MZ header
    and     ebx, 0xFFFF0000         ; align to 64KB

.scan_mz:
    ; Safety bound: don't scan into the null page
    cmp     ebx, 0x00010000
    jl      .next_seh_entry

    ; Check for MZ signature (0x5A4D = "MZ")
    cmp     word [ebx], 0x5A4D
    je      .check_pe_sig

    ; Move down one page
    sub     ebx, 0x00001000
    jmp     .scan_mz

.check_pe_sig:
    ; Verify PE signature via e_lfanew
    mov     ecx, [ebx + 0x3c]       ; ECX = e_lfanew (RVA to IMAGE_NT_HEADERS)
    add     ecx, ebx                ; ECX = absolute NT headers address

    ; Check "PE\0\0" signature
    cmp     dword [ecx], 0x00004550
    jne     .next_seh_entry

    ; We have a valid PE — now check if it's kernel32
    ; Verify by checking export table for known function names
    ; (simplified: check if it exports GetProcAddress)
    ; For brevity, we assume first valid PE found in SEH chain is kernel32
    ; In practice, additional validation is required
    mov     eax, ebx
    ret

.next_seh_entry:
    mov     esi, [esi]              ; follow Next pointer
    jmp     .seh_walk

.seh_fail:
    xor     eax, eax
    ret
```

The SEH approach requires additional validation (export name check) to confirm the found PE is actually kernel32. Production shellcode should use PEB walking instead.

---

## Technique 4: TopLevelExceptionFilter / Unhandled Exception Filter

### Overview

The Windows API `SetUnhandledExceptionFilter` stores its argument (the filter function pointer) in a global variable within kernel32's data section. On some Windows versions, this variable can be read by locating the code in `UnhandledExceptionFilter` and extracting the pointer. However, this technique requires already having located kernel32 (to read its exports) or having a known offset — creating a circular dependency.

The technique is occasionally used in its inverse form: shellcode calls `SetUnhandledExceptionFilter(address_in_shellcode)`, which writes the shellcode address into kernel32 memory. This is primarily used in exploit chains to pass control, not to find kernel32.

### Practical Use in Shellcode

This technique is rarely used for kernel32 location in shellcode. It is mentioned here because it appears in exploit research and provides an alternative code-flow-hijacking primitive.

---

## Technique 5: Stack Scanning

### Overview

When the initial thread starts in a Windows process, the call stack contains return addresses pointing into kernel32 (`BaseThreadInitThunk` and related functions). By walking the stack upward (toward higher addresses, since the stack grows down), shellcode can find return addresses that fall within a kernel32-mapped region.

### Algorithm

1. Read the current stack pointer (ESP).
2. Walk upward in pointer-size increments.
3. For each value, check if it looks like a code address (e.g., > 0x10000 and < 0x80000000 for user-mode).
4. Align the address down to find the PE header.
5. Check for MZ/PE signature and compare module name.

### Why This Is Environment-Dependent

- Shellcode that arrives via a buffer overflow or ROP chain may have a significantly modified or corrupted stack. The original thread startup frames may be overwritten.
- On multi-stage payloads injected into a running thread, the thread's call stack reflects the current call context (e.g., deep in application code), not the thread startup path.
- ASLR means the address range to check varies per run.
- This technique is generally less reliable than PEB walking.

```asm
; ============================================================
; find_kernel32_stack - stack scanning (demonstrative only)
; Unreliable in exploit scenarios — do not use in production shellcode
; ============================================================

find_kernel32_stack:
    mov     esi, esp                ; ESI = current stack pointer

.stack_scan:
    add     esi, 4                  ; advance one DWORD up the stack
    cmp     esi, 0x00400000         ; arbitrary upper bound check
    jge     .stack_fail

    mov     ebx, [esi]              ; EBX = potential return address

    ; Basic sanity: must be in reasonable user-mode range
    cmp     ebx, 0x00010000
    jl      .stack_scan
    cmp     ebx, 0x80000000
    jge     .stack_scan

    ; Align to 64KB
    and     ebx, 0xFFFF0000

.stack_check_mz:
    cmp     ebx, 0x00010000
    jl      .stack_scan

    cmp     word [ebx], 0x5A4D      ; MZ check
    jne     .stack_dec

    mov     ecx, [ebx + 0x3c]
    add     ecx, ebx
    cmp     dword [ecx], 0x00004550 ; PE check
    jne     .stack_dec

    ; Found a PE — validate it's kernel32 (name comparison omitted here)
    mov     eax, ebx
    ret

.stack_dec:
    sub     ebx, 0x10000
    jmp     .stack_check_mz

.stack_fail:
    xor     eax, eax
    ret
```

---

## Name Comparison Deep Dive

### Why Name Comparison Is Necessary

On modern Windows, the initialization order of loaded modules is non-deterministic. The only safe way to identify kernel32 is to compare the module name stored in its LDR entry against the expected string.

### UNICODE_STRING Layout

```c
typedef struct _UNICODE_STRING {
    USHORT  Length;        // 2 bytes: byte-length of string (not null-terminated)
    USHORT  MaximumLength; // 2 bytes: byte-length of Buffer allocation
    PWSTR   Buffer;        // 4 bytes (x86) or 8 bytes (x64): pointer to wide chars
} UNICODE_STRING;
```

For kernel32: `Length = 0x18` (24 bytes = 12 Unicode characters), Buffer points to L"KERNEL32.DLL".

### The Unicode Bytes

L"KERNEL32.DLL" in memory (little-endian):

```
4B 00  = 'K'
45 00  = 'E'
52 00  = 'R'
4E 00  = 'N'
45 00  = 'E'
4C 00  = 'L'
33 00  = '3'
32 00  = '2'
2E 00  = '.'
44 00  = 'D'
4C 00  = 'L'
4C 00  = 'L'
```

As DWORDs (groups of 4 bytes):
```
[+0x00] = 0x0045004B  ('K','E')
[+0x04] = 0x004E0052  ('R','N')
[+0x08] = 0x004C0045  ('E','L')
[+0x0c] = 0x00320033  ('3','2')
[+0x10] = 0x0044002E  ('.','D')
[+0x14] = 0x004C004C  ('L','L')
```

### Optimized Assembly Comparison

```asm
; Input: ESI = pointer to UNICODE_STRING Buffer (BaseDllName.Buffer)
;        ECX = BaseDllName.Length
; Output: ZF set if match (use je after this block), cleared if no match

    cmp     ecx, 0x18               ; kernel32.dll = 12 chars * 2 = 24 bytes
    jne     not_kernel32
    mov     eax, [esi + 0x0]        ; "KE" in unicode
    cmp     eax, 0x0045004B
    jne     not_kernel32
    mov     eax, [esi + 0x4]        ; "RN"
    cmp     eax, 0x004E0052
    jne     not_kernel32
    mov     eax, [esi + 0x8]        ; "EL"
    cmp     eax, 0x004C0045
    jne     not_kernel32
    mov     eax, [esi + 0xc]        ; "32"
    cmp     eax, 0x00320033
    jne     not_kernel32
    mov     eax, [esi + 0x10]       ; ".D"
    cmp     eax, 0x0044002E
    jne     not_kernel32
    mov     eax, [esi + 0x14]       ; "LL"
    cmp     eax, 0x004C004C
    jne     not_kernel32
    ; Falls through — name matches
```

### Handling the First Process Module (NULL Entry Issue)

The very first entry in the InLoadOrderModuleList is the process's own executable image. Its `BaseDllName` might be something like "notepad.exe" or "svchost.exe". The length check (0x18) will quickly dismiss most entries that are not exactly 12 characters. This is an efficient pre-filter.

---

## WinDbg Verification Workflows

### Verify Kernel32 Base Address

```windbg
; List kernel32 in the module list
lm m kernel32

; Example output:
; start    end        module name
; 75f10000 76050000   KERNEL32   (deferred)

; Full PEB inspection
!peb

; Check Ldr manually
dt ntdll!_PEB_LDR_DATA poi(poi(@$peb + 0x0c))

; Walk InLoadOrderModuleList from the first entry
dt ntdll!_LDR_DATA_TABLE_ENTRY poi(poi(poi(@$peb + 0x0c) + 0x0c))
```

### Manually Reproduce the PEB Walk

```windbg
; Step through each entry:
; Entry 1 (usually the process itself)
r $t0 = poi(poi(@$peb + 0x0c) + 0x0c)   ; first Flink
dt ntdll!_LDR_DATA_TABLE_ENTRY @$t0

; Entry 2
r $t0 = poi(@$t0)
dt ntdll!_LDR_DATA_TABLE_ENTRY @$t0

; Continue until you see BaseDllName = "KERNEL32.DLL"
; Check BaseDllName offset:
dt ntdll!_LDR_DATA_TABLE_ENTRY @$t0 BaseDllName
```

### Set a Breakpoint to Verify Find_Kernel32 Returns Correct Value

```windbg
; Set a breakpoint just after your find_kernel32 call
; Then verify EAX matches the known base:
? eax
lm m kernel32
; Base addresses should match
```

### Dump the InInitializationOrderModuleList Explicitly

```windbg
; PEB_LDR_DATA + 0x1c = InInitializationOrderModuleList.Flink
r $t1 = poi(poi(@$peb + 0x0c) + 0x1c)

; First entry via InInitOrderLinks (LDR entry starts at -0x10)
dt ntdll!_LDR_DATA_TABLE_ENTRY (@$t1 - 0x10)

; Get BaseDllName of first entry
dt ntdll!_UNICODE_STRING ((@$t1 - 0x10) + 0x2c)
```

---

## x86 vs x64 Differences

### Register and Segment Differences

| Field | x86 | x64 |
|---|---|---|
| TEB access | FS segment | GS segment |
| TEB.PEB offset | 0x30 | 0x60 |
| PEB.Ldr offset | 0x0c | 0x18 |
| PEB_LDR_DATA InLoadOrderModuleList.Flink offset | 0x0c | 0x10 |
| PEB_LDR_DATA InInitOrderModuleList.Flink offset | 0x1c | 0x30 |
| LDR_DATA_TABLE_ENTRY.DllBase | +0x18 | +0x30 |
| LDR_DATA_TABLE_ENTRY.BaseDllName.Length | +0x2c | +0x58 |
| LDR_DATA_TABLE_ENTRY.BaseDllName.Buffer | +0x30 | +0x60 |
| UNICODE_STRING.Buffer offset | +0x04 | +0x08 |

### x64 PEB Walk Example

```asm
; x64 find_kernel32 using InLoadOrderModuleList
; Returns: RAX = kernel32 base address

find_kernel32_x64:
    xor     rax, rax
    mov     rax, gs:[rax + 0x60]    ; RAX = PEB (GS:0x60 on x64)
    mov     rax, [rax + 0x18]       ; RAX = PEB.Ldr (offset 0x18 in x64 PEB)

    ; InLoadOrderModuleList head at PEB_LDR_DATA + 0x10 (x64)
    lea     rbx, [rax + 0x10]       ; RBX = list head
    mov     rsi, [rax + 0x10]       ; RSI = first Flink

.loop64:
    cmp     rsi, rbx
    je      .fail64

    ; BaseDllName.Length at x64 LDR entry + 0x58
    movzx   ecx, word [rsi + 0x58]
    cmp     ecx, 0x18               ; 24 bytes = "KERNEL32.DLL"
    jne     .next64

    ; BaseDllName.Buffer at x64 LDR entry + 0x60
    mov     rdi, [rsi + 0x60]       ; pointer to wide string

    ; Compare name (same byte patterns as x86)
    mov     eax, [rdi + 0x00]
    cmp     eax, 0x0045004B         ; "KE"
    jne     .next64

    mov     eax, [rdi + 0x04]
    cmp     eax, 0x004E0052         ; "RN"
    jne     .next64

    mov     eax, [rdi + 0x08]
    cmp     eax, 0x004C0045         ; "EL"
    jne     .next64

    mov     eax, [rdi + 0x0c]
    cmp     eax, 0x00320033         ; "32"
    jne     .next64

    mov     eax, [rdi + 0x10]
    cmp     eax, 0x0044002E         ; ".D"
    jne     .next64

    mov     eax, [rdi + 0x14]
    cmp     eax, 0x004C004C         ; "LL"
    jne     .next64

    ; DllBase at x64 LDR entry + 0x30
    mov     rax, [rsi + 0x30]
    ret

.next64:
    mov     rsi, [rsi]              ; follow Flink (8-byte pointer)
    jmp     .loop64

.fail64:
    xor     rax, rax
    ret
```

### x64 No pushad/popad

In 32-bit shellcode, `pushad` is commonly used to save all registers before calling a helper routine. x64 provides no equivalent instruction. All register saving must be done explicitly:
```asm
; x64 manual register save
push    rbx
push    rsi
push    rdi
; ... call helper ...
pop     rdi
pop     rsi
pop     rbx
```

---

## Common Mistakes

### Mistake 1: Applying InInitOrderLinks Offsets to InLoadOrderLinks (or vice versa)

The two most common list entry pointers give different base addresses:
- Following `InInitializationOrderModuleList.Flink` gives a pointer to `InInitializationOrderLinks` at `LDR_DATA_TABLE_ENTRY + 0x10`.
- Following `InLoadOrderModuleList.Flink` gives a pointer to `InLoadOrderLinks` at `LDR_DATA_TABLE_ENTRY + 0x00`.

Using offsets for one when you followed the other is the single most common source of garbage reads:
```asm
; WRONG: followed InInitOrderModuleList.Flink but used InLoadOrder offsets
mov esi, [eax + 0x1c]   ; InInitOrderModuleList.Flink
mov ebx, [esi + 0x18]   ; WRONG: this is InLoadOrder DllBase offset,
                         ;         but InInitOrderLinks is at +0x10 in the entry
                         ; correct would be [esi + 0x08]
```

### Mistake 2: Assuming a Specific Module Position in the List

Hardcoding "skip the first entry" or "the third entry is kernel32" breaks on any Windows version other than the one tested:
```asm
; WRONG
mov esi, [eax + 0x1c]   ; first Flink
mov esi, [esi]           ; skip first
mov esi, [esi]           ; skip second  -- kernel32 is NOT always here
mov ebx, [esi + 0x08]   ; DllBase -- may be KernelBase or another module
```
Always compare BaseDllName.

### Mistake 3: Not Saving the List Head for Termination

Without a proper termination check, the list walk continues indefinitely after visiting all entries (because the list is circular and wraps back to the first entry):
```asm
; WRONG — no termination check
.loop:
    mov esi, [esi]      ; keeps following Flink forever
    jmp .loop           ; infinite loop or crash when looping back to head
```

### Mistake 4: Confusing Length with MaximumLength in UNICODE_STRING

Some code reads `word [esi + 0x2c]` (Length) but compares against MaximumLength values (which may be larger due to over-allocation). Always compare against `Length`, not `MaximumLength`:
```
UNICODE_STRING + 0x00 = Length (USHORT)         -- use this
UNICODE_STRING + 0x02 = MaximumLength (USHORT)  -- not this
UNICODE_STRING + 0x04 = Buffer (PWSTR)
```

### Mistake 5: Forgetting That UNICODE_STRING.Buffer Uses Wide Characters

Comparing L"KERNEL32.DLL" against an ASCII "KERNEL32.DLL" string will fail. The Buffer contains 2-byte-per-character Unicode (UTF-16LE). All comparison values must account for the null high bytes:
```asm
; WRONG: comparing ASCII
cmp dword [edi], 0x4E52454B   ; "KERN" in ASCII — wrong for Unicode buffer
; CORRECT: comparing Unicode
cmp dword [edi], 0x0045004B   ; L"KE" in little-endian Unicode
```
