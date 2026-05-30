# PEB_LDR_DATA — Loader Data Block (`_PEB_LDR_DATA`)

## Purpose

`PEB_LDR_DATA` is the structure that the Windows loader (`ntdll!LdrpInitializeProcess` and its helpers) uses to maintain bookkeeping on every DLL loaded into a process. It acts as the header for three separate doubly-linked lists, each containing one entry per loaded module, sorted or ordered in a different way. The PEB's `Ldr` field points to this structure, making it the single root from which shellcode can enumerate all loaded modules.

The structure is allocated from the process heap (or a loader-private heap in newer Windows) during early process initialization, before `LdrpInitializeProcess` calls the application's entry point. The loader writes to `PEB_LDR_DATA` every time it loads or unloads a DLL — adding entries to all three lists, setting the `Initialized` flag when done, and updating `Length`.

**Why three separate lists?** Different consumers of the module list have different traversal requirements. The loader itself needs to process DLLs in the correct initialization order (dependencies before dependents). A memory manager walking the address space to update permission maps needs modules sorted by virtual address. Debuggers want to enumerate modules in the order they were loaded to reproduce the loading timeline. Rather than maintaining one list and sorting it differently for each consumer, the loader maintains three independent lists simultaneously. Each `LDR_DATA_TABLE_ENTRY` (one per module) contains three `LIST_ENTRY` fields, one per list, so the same node participates in all three lists simultaneously at zero extra memory cost.

**Where it lives:** A pointer to `PEB_LDR_DATA` is stored in `PEB.Ldr` (+0x00C on x86, +0x018 on x64). The structure itself is allocated in the process's early loader heap, typically at a static address on older systems but randomized (ASLR) on modern Windows. Its absolute address is irrelevant to shellcode — you always reach it through `PEB.Ldr`.

---

## Exploit Relevance

`PEB_LDR_DATA` is the **pivot point** between the PEB and the actual module entries. Shellcode that has obtained the PEB address next reads `PEB.Ldr` to get `PEB_LDR_DATA*`, then reads one of the three list head fields to start walking loaded modules. The choice of which list to walk determines the traversal order and the delta arithmetic needed to compute `DllBase` from each list link (see `LDR_DATA_TABLE_ENTRY.md`).

The structure is also relevant to:
- **EDR module hiding detection:** Security tools verify that all loaded DLLs appear in all three lists. Missing entries (unlinked modules) indicate a hidden DLL or shellcode that manually unlinked itself.
- **Anti-debug via loader state:** Checking `Initialized` can reveal whether the shellcode is running before normal process initialization has completed (e.g., in a process hollowing scenario where the loader state is incomplete).

---

## Full Structure Layout

| Field Name | Type | x86 Offset (hex/dec) | x64 Offset (hex/dec) | Purpose |
|---|---|---|---|---|
| `Length` | ULONG | 0x000 / 0 | 0x000 / 0 | Size of this structure in bytes |
| `Initialized` | BOOLEAN | 0x004 / 4 | 0x004 / 4 | TRUE once loader has finished populating lists |
| *(padding)* | — | — | 0x005–0x007 | 3 bytes alignment padding before pointer on x64 |
| `SsHandle` | PVOID | 0x008 / 8 | 0x008 / 8 | Subsystem handle; always NULL in Win32 processes |
| `InLoadOrderModuleList` | `LIST_ENTRY` | 0x00C / 12 | 0x010 / 16 | Doubly-linked list of modules in load order |
| `InMemoryOrderModuleList` | `LIST_ENTRY` | 0x014 / 20 | 0x020 / 32 | Doubly-linked list of modules sorted by VMA |
| `InInitializationOrderModuleList` | `LIST_ENTRY` | 0x01C / 28 | 0x030 / 48 | Doubly-linked list in DLL_PROCESS_ATTACH order |
| `EntryInProgress` | PVOID | 0x024 / 36 | 0x040 / 64 | Currently-loading module entry (during load) |
| `ShutdownInProgress` | BOOLEAN | 0x028 / 40 | 0x048 / 72 | TRUE during process shutdown |
| *(padding)* | — | — | 0x049–0x04F | 7 bytes padding to align next pointer on x64 |
| `ShutdownThreadId` | PVOID | 0x02C / 44 | 0x050 / 80 | Thread ID performing shutdown |

**Note on `Length`:** On Windows 7 SP1 x86, `Length` = `0x28` (40 bytes). On Windows 10 x64, `Length` = `0x58` (88 bytes). The structure has grown with OS versions. Shellcode ignores `Length`.

**Note on `SsHandle`:** Always NULL in Win32 subsystem processes. Non-NULL only in POSIX or OS/2 subsystem processes (historical, not relevant on modern Windows).

---

## Deep Field Explanations

### `Length` (+0x000) — Why Shellcode Ignores It

`Length` is set by the loader to the size of `_PEB_LDR_DATA` at the time of the loader's compilation. It serves as a version indicator — code that wants to know which fields are present in this loader version can check `Length` and compare against known sizes. However, shellcode does not dynamically probe structure sizes: shellcode targets specific Windows versions with known offsets, compiled in. A shellcode targeting Windows 10 knows that `PEB_LDR_DATA.InInitializationOrderModuleList` is at `0x030` on x64, and does not need to verify `Length` first. Reading `Length` before accessing fields would add unnecessary instructions and potential null bytes.

### `Initialized` (+0x004) — What "Not Initialized" Means for Shellcode

`Initialized` is set to `FALSE` (0) by the loader at the start of `LdrpInitializeProcess` and set to `TRUE` (1) after the module lists have been populated and all required DLLs have been loaded. If shellcode runs in a context where `Initialized` is still 0 — for example, inside a process that was hollowed before loader initialization completed — then the module lists may be empty or partially constructed. Walking an incomplete list could lead to reading uninitialized memory or looping forever on a corrupted `Flink`.

In practice, most shellcode runs after the loader has completed (the exploit fires in a running application), so `Initialized` is always 1. But shellcode injected at `ProcessCreationFlags = CREATE_SUSPENDED` and running before `ntdll` initialization completes (very early injection) needs to wait or verify this flag.

### `InLoadOrderModuleList` (+0x00C x86 / +0x010 x64)

**What load order means:** The load order list records modules in the chronological sequence in which they were mapped into the process. The first module is always the main executable (the `.exe`). The second is typically `ntdll.dll`, because the kernel maps it before anything else. After that, modules appear in the order the loader resolved and loaded them.

**Load order is primarily a debugging artifact** — the loader uses it to quickly find a module by name during `LdrGetDllHandle` style lookups (linear scan, but with quick hash-based shortcuts in newer Windows). For shellcode, walking the load order list requires the most delta arithmetic because `InLoadOrderLinks` is at offset `+0x000` in `LDR_DATA_TABLE_ENTRY` — meaning the list's Flink/Blink pointers point directly at the start of each entry. `DllBase` is then at a delta of `+0x018` from the start of the entry.

**Standard load order on a minimal process:**
1. Main executable (`target.exe`)
2. `ntdll.dll`
3. `kernel32.dll`
4. `kernelbase.dll` (Windows 7+)
5. Further DLLs in import resolution order

### `InMemoryOrderModuleList` (+0x014 x86 / +0x020 x64)

**What memory order means:** The memory order list sorts modules by their base virtual address — lowest image base first. This is analogous to sorting by `DllBase`. The list facilitates efficient range queries: "which module owns this virtual address?" can be answered by a binary-search-like walk of this list rather than a linear scan of all modules.

**Memory order is rarely used by shellcode** because there is no consistent prediction of which module will have the lowest base address (ASLR randomizes module bases independently). The main executable is usually at a predictable low address (0x400000 in older builds, randomized with ASLR in modern builds), but `ntdll` and `kernel32` locations vary.

**The delta for memory-order traversal:** When the list head's Flink points into the next entry, it points at that entry's `InMemoryOrderLinks` field, which is at offset `+0x008` (x86) or `+0x010` (x64) within `LDR_DATA_TABLE_ENTRY`. To find `DllBase` (+0x018 x86 / +0x030 x64 from the entry start), you subtract the `InMemoryOrderLinks` offset from the `DllBase` offset:
- x86: DllBase delta = `0x018 - 0x008 = 0x010`
- x64: DllBase delta = `0x030 - 0x010 = 0x020`

### `InInitializationOrderModuleList` (+0x01C x86 / +0x030 x64)

**What initialization order means:** This list records the sequence in which `DLL_PROCESS_ATTACH` notifications were dispatched. A module's `DllMain` with `DLL_PROCESS_ATTACH` is called during initialization; the order follows dependency resolution. Specifically:
- A DLL is only initialized after all its dependencies have been initialized.
- The OS loader performs a topological sort of the dependency graph and calls `DllMain` in that order.
- The executable's own entry point is called last (after all imported DLLs are initialized).

**Why classic shellcode uses this list:** On Windows XP and early Windows Vista/7, the initialization order placed modules in a highly predictable sequence:
1. `ntdll.dll` — always first (the loader itself, initialized before everything else)
2. `kernel32.dll` (or `kernelbase.dll` on Windows 7+)
3. Further DLLs

This predictability meant shellcode could hard-code "take the second entry in the initialization list, and you have kernel32." However, this assumption became unreliable on Windows 7+ due to `kernelbase.dll` splitting `kernel32.dll`'s functionality.

**The delta for init-order traversal (most important):** The list head's Flink points at the `InInitializationOrderLinks` field within `LDR_DATA_TABLE_ENTRY`. That field is at offset `+0x010` (x86) or `+0x020` (x64) within the entry. To reach `DllBase`:
- x86: `0x018 - 0x010 = 0x008` — access `[ESI+0x08]` to read DllBase when ESI is the InInitializationOrderLinks pointer
- x64: `0x030 - 0x020 = 0x010` — access `[RSI+0x10]`

This delta of `0x08` (x86) is what makes the classic shellcode instruction `mov ebx, [esi+8h]` correct. It is not an arbitrary constant — it is the algebraic difference between the `InInitializationOrderLinks` field offset and the `DllBase` field offset within the same `LDR_DATA_TABLE_ENTRY`.

---

## The `LIST_ENTRY` Structure and Why It Points Into the Middle

This is the most important conceptual hurdle in understanding PEB walk shellcode.

### `LIST_ENTRY` Layout

```
_LIST_ENTRY:
  +0x000  Flink  PLIST_ENTRY  <- pointer to next LIST_ENTRY in chain
  +0x004  Blink  PLIST_ENTRY  <- pointer to previous LIST_ENTRY in chain
```

`LIST_ENTRY` is an intrusive doubly-linked list mechanism. Each `LDR_DATA_TABLE_ENTRY` embeds three `LIST_ENTRY` structures (one per list) directly inside itself as fields. When the loader links a module into the `InInitializationOrderModuleList`, it sets:
- The new entry's `InInitializationOrderLinks.Flink` to point at the list head's next entry.
- The new entry's `InInitializationOrderLinks.Blink` to point at the previous tail.
- The neighboring entries' `Flink`/`Blink` values to point at the new entry's `InInitializationOrderLinks` field.

The critical implication: **Flink and Blink point at `LIST_ENTRY` fields within entries, not at the start of entries.** When you read `InInitializationOrderModuleList.Flink` from `PEB_LDR_DATA`, you get an address that is `0x010` bytes (x86) past the start of the first `LDR_DATA_TABLE_ENTRY`. To find the start of that entry, you would subtract `0x010`. To find `DllBase` (at entry start + `0x018`), you add `0x018 - 0x010 = 0x008` to the pointer you have.

### Diagram: Memory Layout

```
PEB_LDR_DATA                  LDR_DATA_TABLE_ENTRY (ntdll.dll)
+0x000  Length                +0x000  InLoadOrderLinks.Flink       --+
+0x004  Initialized           +0x004  InLoadOrderLinks.Blink         |
+0x008  SsHandle              +0x008  InMemoryOrderLinks.Flink       |
+0x00C  InLoadOrderModuleList               [Flink/Blink]            |
  +0x00C  Flink  ──────────────────────────────────────────────────> |
  +0x010  Blink  <── (tail)                                          |
+0x014  InMemoryOrderModuleList                                       |
  +0x014  Flink  ────────────── points to InMemoryOrderLinks.Flink   |
  +0x018  Blink                 of the first entry                   |
+0x01C  InInitializationOrderModuleList                              |
  +0x01C  Flink  ──[A]──────────────────────────────────────────+    |
  +0x020  Blink                                                 |    |
                                                                v    |
                            +0x010  InInitializationOrderLinks.Flink | <── [A] points HERE
                            +0x014  InInitializationOrderLinks.Blink |
                            +0x018  DllBase  <──────── add 0x08 from [A]
                            +0x01C  EntryPoint
                            +0x020  SizeOfImage
                            ...
                            +0x028  FullDllName (UNICODE_STRING)
                            +0x030  BaseDllName (UNICODE_STRING)
```

When shellcode does `mov   esi, [esi+0x1c]` (read the Flink from `InInitializationOrderModuleList`), ESI becomes address `[A]` — a pointer to offset `+0x010` within the first `LDR_DATA_TABLE_ENTRY`. Then `[ESI+0x08]` reads offset `0x010 + 0x008 = 0x018` within the entry, which is `DllBase`. This is **not** a coincidence or magic number; it is precise delta arithmetic.

### Forward and Backward Links (`Flink` and `Blink`)

`Flink` (Forward Link) points to the next `LIST_ENTRY` in the list. `Blink` (Backward Link) points to the previous one. The list is circular: the last entry's `Flink` points back to the list head inside `PEB_LDR_DATA`, and the head's `Blink` points at the last entry's `LIST_ENTRY`. Shellcode walking forward iterates through `Flink`s and stops when `Flink` points back into the `PEB_LDR_DATA` structure (the sentinel list head). One way to detect this: the Flink points into the `PEB_LDR_DATA` address range rather than into the module list entries' address range. Alternatively, check that the corresponding `DllBase` is non-zero.

---

## WinDbg Verification

### Dump the Structure Directly

```
0:000> dt ntdll!_PEB_LDR_DATA 0x77c75880
   +0x000 Length                          : 0x28
   +0x004 Initialized                     : 0x1 ''
   +0x008 SsHandle                        : (null)
   +0x00c InLoadOrderModuleList           : _LIST_ENTRY [ 0x841f20 - 0x8421c0 ]
   +0x014 InMemoryOrderModuleList         : _LIST_ENTRY [ 0x841f28 - 0x8421c8 ]
   +0x01c InInitializationOrderModuleList : _LIST_ENTRY [ 0x841fa8 - 0x842248 ]
   +0x024 EntryInProgress                 : (null)
   +0x028 ShutdownInProgress              : 0 ''
   +0x02c ShutdownThreadId                : (null)
```

**Reading this output:** The `InInitializationOrderModuleList` shows `Flink = 0x841fa8` and `Blink = 0x842248`. The Flink `0x841fa8` is the `InInitializationOrderLinks` field of the first real entry (ntdll.dll). To get the entry's start, subtract the `InInitializationOrderLinks` offset within the entry (0x10), giving entry start = `0x841fa8 - 0x10 = 0x841f98`. But shellcode does not need the entry start — it adds 0x08 to `0x841fa8` to get `DllBase` directly: `dd 0x841fa8+8 L1`.

### Walk the Module List with `dt`

```
0:000> dt ntdll!_LDR_DATA_TABLE_ENTRY 0x841f98
   +0x000 InLoadOrderLinks           : _LIST_ENTRY [ 0x841f20 - 0x77c75880+c ]
   +0x008 InMemoryOrderLinks         : _LIST_ENTRY [ 0x841f28 - 0x77c75880+14 ]
   +0x010 InInitializationOrderLinks : _LIST_ENTRY [ 0x841fa8 - 0x77c75880+1c ]
   +0x018 DllBase                    : 0x77b00000 Void
   +0x01c EntryPoint                 : 0x77b4c3c0 Void
   +0x020 SizeOfImage                : 0x1a8000
   +0x024 FullDllName                : _UNICODE_STRING "C:\Windows\SysWOW64\ntdll.dll"
   +0x02c BaseDllName                : _UNICODE_STRING "ntdll.dll"
```

**Note:** Entry at `0x841f98` is ntdll.dll (DllBase = 0x77b00000). The Flink of `InInitializationOrderLinks` is `0x841fa8` — this is the `InInitializationOrderLinks.Flink` we read from `PEB_LDR_DATA`. Confirm: `0x841f98 + 0x10 = 0x841fa8`. Correct.

### Walk to the Next Module

```
0:000> dt ntdll!_LDR_DATA_TABLE_ENTRY (0x841fa8 - 0x10)
   +0x018 DllBase  : 0x75c40000  ; This is kernel32.dll (or kernelbase.dll on Win7+)
   +0x02c BaseDllName : _UNICODE_STRING "KERNEL32.DLL"
```

Or equivalently, using the Flink chain:
```
0:000> dd 0x841fa8 L2
00841fa8  00842128 00841f98  ; Flink = 0x842128 (next entry's InInitOrderLinks), Blink
0:000> dd 0x842128+8 L1
00842130  75c40000          ; DllBase of next module = 0x75c40000
```

### Confirm the List Head Sentinel

```
0:000> dd 0x842248 L2
00842248  77c7589c 00841f20  ; Flink = 0x77c7589c = PEB_LDR_DATA + 0x1c (the list head itself)
; When Flink points back into PEB_LDR_DATA range, we have walked the entire list
```

---

## Assembly Walkthrough

### Full Init-Order List Walk with Null Guard

```asm
; ─── Walk InInitializationOrderModuleList ────────────────────────────────────
;
; On entry: nothing assumed
; On exit:  EBX = DllBase of kernel32.dll (or 0 if not found)
;           EDI = BaseDllName.Buffer pointer (unicode string)
;
; Registers used:
;   ESI = current InInitializationOrderLinks pointer (within LDR_DATA_TABLE_ENTRY)
;   EBX = candidate DllBase
;   EDI = BaseDllName.Buffer pointer
;   ECX = scratch (set to 0 for null-byte-free FS access)

find_kernel32:
    xor   ecx, ecx              ; ECX = 0

    ; Step 1: Get PEB from TEB
    mov   esi, fs:[ecx+30h]     ; ESI = PEB  (TEB.ProcessEnvironmentBlock)

    ; Step 2: Get PEB_LDR_DATA from PEB
    mov   esi, [esi+0Ch]        ; ESI = PEB.Ldr = &PEB_LDR_DATA
                                ; +0x0C because Ldr is at PEB offset 0x0C on x86

    ; Step 3: Get first InInitializationOrderLinks from PEB_LDR_DATA
    mov   esi, [esi+1Ch]        ; ESI = PEB_LDR_DATA.InInitializationOrderModuleList.Flink
                                ; +0x1C because InInitializationOrderModuleList is at
                                ; PEB_LDR_DATA offset 0x1C on x86.
                                ; This Flink points to InInitializationOrderLinks.Flink
                                ; WITHIN the first LDR_DATA_TABLE_ENTRY
                                ; (i.e., entry_start + 0x10)

next_module:
    ; Guard: check for null DllBase before reading the name buffer
    ; This catches the list head sentinel and any incomplete entries
    mov   ebx, [esi+08h]        ; EBX = DllBase
                                ; ESI points at InInitializationOrderLinks (+0x10 in entry)
                                ; DllBase is at entry+0x18; delta = 0x18 - 0x10 = 0x08

    test  ebx, ebx              ; Is DllBase zero?
    je    not_found             ; If so, we hit the sentinel or an unloaded module

    mov   edi, [esi+20h]        ; EDI = BaseDllName.Buffer
                                ; BaseDllName is UNICODE_STRING at entry+0x2C (x86)
                                ; Buffer is UNICODE_STRING+0x04 = entry+0x30
                                ; Delta from InInitOrderLinks: 0x30 - 0x10 = 0x20

    mov   esi, [esi]            ; ESI = next InInitializationOrderLinks (Flink)
                                ; Advance BEFORE the test so we don't need
                                ; to revisit this entry on the next iteration

    ; Test: is BaseDllName exactly 12 wide characters (24 bytes)?
    ; kernel32.dll = 12 chars × 2 bytes/wchar = 24 bytes = 0x18
    ; We check that character at index 12 (byte offset 24 = 0x18) is zero.
    ; A 12-char name has indices 0..11 valid, index 12 is the null terminator.
    cmp   word [edi+12*2], cx   ; Is wchar at offset 24 equal to 0 (CX=0)?
    jne   next_module           ; Not 12 chars, skip

    ; Optional additional check: verify first char is 'k' (0x006B in UTF-16LE)
    ; This distinguishes from other 12-char DLLs (rare but possible)
    cmp   byte [edi], 0x6B      ; First byte of first wchar = 'k' in ASCII/UTF-16LE low byte
    jne   next_module

    ; EBX = kernel32.dll DllBase. Done.
    jmp   found_kernel32

not_found:
    xor   ebx, ebx              ; Return 0 to indicate failure
found_kernel32:
    ; EBX = kernel32 ImageBase (or 0 on failure)
```

### Hash-Based Module Identification (More Robust)

Rather than checking character count and a single byte, production shellcode typically uses a hash of the module name. This avoids false positives and is resilient to unusual module load orders:

```asm
; ─── Hash-based kernel32 identification (ROR-13 approach) ────────────────────
;
; Precondition: ESI = InInitializationOrderLinks pointer (entry+0x10)
;               ECX = 0
;               EDI = BaseDllName.Buffer (pointer to wide chars)
;               compute_hash routine available (see find_function pattern)
;
; The ROR-13 hash of L"KERNEL32.DLL" (uppercased) = 0x6A4ABC5B
; (varies by hash implementation; verify against your find_function)

hash_module_name:
    xor   edx, edx              ; EDX = running hash = 0
    xor   eax, eax              ; EAX = 0

hash_loop:
    lodsb                       ; AL = next byte from [EDI]; EDI++
                                ; LODSB reads the low byte of each wide char
                                ; since UTF-16LE stores ASCII chars as [char, 0x00]
                                ; and we skip the high 0x00 byte on next iteration

    ; OR 0x20 to lowercase if uppercase ASCII letter (A-Z → a-z)
    ; This makes the comparison case-insensitive for ASCII characters
    ; and does not affect digits, dots, or already-lowercase chars
    cmp   al, 0x41              ; below 'A'?
    jb    hash_not_alpha
    cmp   al, 0x5A              ; above 'Z'?
    ja    hash_not_alpha
    or    al, 0x20              ; convert to lowercase
hash_not_alpha:
    test  al, al                ; null terminator (low byte of L'\0')?
    jz    hash_done

    ror   edx, 0x0D             ; ROR hash by 13
    add   edx, eax              ; mix in current byte
    jmp   hash_loop

hash_done:
    ; Skip the 0x00 high byte of the null terminator (lodsb consumed it already
    ; since lodsb reads one byte at a time through the wide string)
    cmp   edx, 0x6A4ABC5B       ; compare against precomputed KERNEL32.DLL hash
    jne   next_module           ; mismatch, try next
    ; EBX = DllBase of kernel32.dll
```

---

## Common Mistakes

### Mistake 1: Confusing the List Head Sentinel with a Real Entry

The `InInitializationOrderModuleList` in `PEB_LDR_DATA` is the **list head** — it is not itself a module entry. Its `Flink` points at the first real entry's `InInitializationOrderLinks` field. Its `Blink` points at the last real entry's same field. When you have walked the entire list and arrive back at the `PEB_LDR_DATA` address range, you have hit the sentinel. Shellcode that does not detect the sentinel will read the `PEB_LDR_DATA` fields as if they were an `LDR_DATA_TABLE_ENTRY`, producing garbage `DllBase` and `BaseDllName` values, and typically crashing when it tries to dereference `BaseDllName.Buffer`.

**Detection:** The sentinel entry's "DllBase" (reading at `[esi+0x08]` when ESI is the list head Flink) reads from `PEB_LDR_DATA` offset `0x10 + 0x08 = 0x18`, which is the `InMemoryOrderModuleList` list head — a pointer that is never `0`. This means a null-DllBase check alone is insufficient as a sentinel detector. The robust approach is to store the `PEB_LDR_DATA` address before the loop and compare `ESI - 0x10` against it on each iteration.

### Mistake 2: Assuming ntdll Is Always Initialization Order Index 0

`ntdll.dll` appears first in the initialization order list because it is the loader itself — it initializes itself before calling any other DLL's `DllMain`. This is consistent across all Windows versions. However, shellcode that hard-codes "skip 1 entry to get kernel32" will fail on Windows 7+ where `kernelbase.dll` may appear between ntdll and kernel32, or on systems with API set DLLs inserted into the list. Always walk the list and identify modules by name or name hash.

### Mistake 3: Off-by-One in the Delta Calculation

The delta arithmetic for `InInitializationOrderLinks` is `0x08` on x86 for reaching `DllBase`. A common error is computing the delta against `InLoadOrderLinks` (+0x000 in the entry) instead of `InInitializationOrderLinks` (+0x010 in the entry). If you read the Flink from `InLoadOrderModuleList` and then use `[esi+0x08]` for DllBase, you are wrong — the correct delta for load-order walking is `[esi+0x18]` because DllBase (+0x018) relative to the entry start (+0x000) = 0x018.

Summary of deltas on x86:
- Walking via InLoadOrderModuleList → DllBase at `[entry+0x18]` = `[flink+0x18]`
- Walking via InMemoryOrderModuleList → DllBase at `[flink+0x10]` (0x18 - 0x08 = 0x10)
- Walking via InInitializationOrderModuleList → DllBase at `[flink+0x08]` (0x18 - 0x10 = 0x08)

### Mistake 4: Not Handling Uppercase vs. Lowercase Module Names

On some Windows versions and configurations, `BaseDllName.Buffer` may contain `KERNEL32.DLL` (all uppercase) or `kernel32.dll` (all lowercase). This is system-specific and can differ between service packs. Shellcode comparing individual characters must either normalize case or use a case-insensitive hash. The length-check approach (checking character count to find 12-char names) avoids case sensitivity for the primary check, but the optional byte comparison is case-sensitive. Production shellcode should either use a case-folding hash or compare with both cases.

### Mistake 5: Reading `BaseDllName.Length` for Character Count

`UNICODE_STRING.Length` is the byte length of the string, not the character count. `kernel32.dll` has 12 characters and each is 2 bytes (UTF-16LE), so `Length = 24 = 0x18`. Shellcode that interprets `Length` as character count and compares with 12 will never match, because `Length` will be `24` (0x18). The comparison must be against the **byte length** value matching the expected character count × 2. See `LDR_DATA_TABLE_ENTRY.md` for more detail on `UNICODE_STRING` layout.

---

## Defensive Caveats

**EDR module list integrity monitoring:** Security products that inject into processes typically verify all three `PEB_LDR_DATA` lists are consistent. A DLL that manually unlinks itself from all three lists (a common rootkit/stealth technique) will be detected by any product that cross-references the lists. More sophisticated products also walk the VAD (Virtual Address Descriptor) tree via kernel callbacks and compare the set of mapped PE images against the PEB lists.

**Loader lock detection:** Some EDRs monitor for attempts to walk the module list without holding `PEB.LoaderLock` (the `RTL_CRITICAL_SECTION` at `PEB+0x0A0`). While shellcode typically runs single-threaded and doesn't need the lock, racing against a legitimate DLL load in a multi-threaded injected context could corrupt list pointers and crash the process — an observable anomaly.

**Hook-based detection:** The `ntdll!LdrGetProcedureAddress` and related functions are commonly hooked. Shellcode that bypasses these by directly walking PEB/LDR structures avoids those hooks — which itself is a behavioral signal. Absence of `LdrGetProcedureAddress` calls combined with suspicious memory reads in the TEB/PEB range is a behavioral cluster that triggers detection.
