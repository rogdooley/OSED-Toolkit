# LDR_DATA_TABLE_ENTRY — Per-Module Loader Metadata Node (`_LDR_DATA_TABLE_ENTRY`)

## Purpose

`LDR_DATA_TABLE_ENTRY` is the loader's per-module metadata node. Every DLL (and the main executable) mapped into a process has exactly one of these structures, allocated by `ntdll!LdrpAllocateDataTableEntry` at load time and deallocated by `ntdll!LdrpFreeDataTableEntry` at unload. The collection of all these entries forms the module list that shellcode walks to find loaded DLLs without calling any Win32 API.

The structure is important because it holds three pieces of information shellcode needs in quick succession: the module's `DllBase` (where the DLL is mapped), its name (to confirm which DLL it is), and its size (for bounds checking). All three are reachable from a single `LDR_DATA_TABLE_ENTRY*`.

### Relationship to PEB_LDR_DATA and the Three Lists

`PEB_LDR_DATA` (pointed to by `PEB.Ldr`) contains three fields that are the heads of three independent doubly-linked lists:

```
PEB_LDR_DATA:
  +0x00C  InLoadOrderModuleList          LIST_ENTRY  (head)
  +0x014  InMemoryOrderModuleList        LIST_ENTRY  (head)
  +0x01C  InInitializationOrderModuleList LIST_ENTRY  (head)
```

Every `LDR_DATA_TABLE_ENTRY` participates in **all three lists simultaneously**. It does this by embedding three separate `LIST_ENTRY` fields at different offsets within its own body. The key consequence is:

- When you follow a `Flink` pointer in `InLoadOrderModuleList`, you get a pointer to the **`InLoadOrderLinks` field** of the next entry — which happens to be at offset `+0x000`, so the pointer IS the entry start.
- When you follow a `Flink` pointer in `InMemoryOrderModuleList`, you get a pointer to the **`InMemoryOrderLinks` field** of the next entry — which is at offset `+0x008`, so you must subtract `0x008` to reach the entry start.
- When you follow a `Flink` pointer in `InInitializationOrderModuleList`, you get a pointer to the **`InInitializationOrderLinks` field** — at offset `+0x010`, so subtract `0x010` to reach entry start.

This offset delta arithmetic is the single most important concept for shellcode that walks these lists. Getting it wrong gives a garbage pointer to somewhere in the middle of the entry, making every subsequent field read incorrect.

---

## Full Structure Layout (x86 / x64)

| Field | x86 Offset | x64 Offset | Type | Purpose |
|---|---|---|---|---|
| `InLoadOrderLinks` | +0x000 / 0 | +0x000 / 0 | LIST_ENTRY | Links in load-order list |
| `InMemoryOrderLinks` | +0x008 / 8 | +0x010 / 16 | LIST_ENTRY | Links in memory-order list |
| `InInitializationOrderLinks` | +0x010 / 16 | +0x020 / 32 | LIST_ENTRY | Links in init-order list |
| `DllBase` | +0x018 / 24 | +0x030 / 48 | PVOID | Module `ImageBase` (mapped address) |
| `EntryPoint` | +0x01C / 28 | +0x038 / 56 | PVOID | `DllMain` or EXE entry point address |
| `SizeOfImage` | +0x020 / 32 | +0x040 / 64 | ULONG | Total size of the mapped image in bytes |
| `FullDllName` | +0x024 / 36 | +0x048 / 72 | UNICODE_STRING | Full path (e.g., `C:\Windows\System32\kernel32.dll`) |
| `BaseDllName` | +0x02C / 44 | +0x058 / 88 | UNICODE_STRING | Filename only (e.g., `KERNEL32.DLL`) |
| `Flags` | +0x034 / 52 | +0x068 / 104 | ULONG | Loader state bitfield (see Flags section) |
| `LoadCount` / `ObsoleteLoadCount` | +0x038 / 56 | +0x06C / 108 | USHORT | Reference count for the loaded module |
| `TlsIndex` | +0x03A / 58 | +0x06E / 110 | USHORT | TLS slot index, or 0 if none |
| `HashLinks` | +0x03C / 60 | +0x070 / 112 | LIST_ENTRY | Links in loader hash table |
| `TimeDateStamp` | +0x044 / 68 | +0x080 / 128 | ULONG | PE header timestamp |
| `EntryPointActivationContext` | +0x048 / 72 | +0x088 / 136 | PVOID | Activation context for `DllMain` |
| `Lock` | +0x04C / 76 | +0x090 / 144 | PVOID | Per-entry loader lock (Win8+) |
| `DdagNode` | +0x050 / 80 | +0x098 / 152 | PVOID | Pointer to `LDR_DDAG_NODE` (Win8+) |
| `NodeModuleLink` | +0x054 / 84 | +0x0A0 / 160 | LIST_ENTRY | Links in `LDR_DDAG_NODE.Modules` list |
| `LoadContext` | +0x05C / 92 | +0x0B0 / 176 | PVOID | Load context (transient, during loading) |
| `ParentDllBase` | +0x060 / 96 | +0x0B8 / 184 | PVOID | `DllBase` of the module that triggered this load |
| `OriginalBase` | +0x064 / 100 | +0x0C0 / 192 | PVOID | Preferred load address from PE headers |
| `LoadTime` | +0x068 / 104 | +0x0C8 / 200 | LARGE_INTEGER | Time of load (100ns intervals since epoch) |
| `BaseNameHashValue` | +0x070 / 112 | +0x0D8 / 216 | ULONG | Hash of `BaseDllName` for fast lookup |
| `LoadReason` | +0x074 / 116 | +0x0DC / 220 | `LDR_DLL_LOAD_REASON` | Why the module was loaded |
| `ImplicitPathOptions` | +0x078 / 120 | +0x0E0 / 224 | ULONG | Path search options |
| `ReferenceCount` | +0x07C / 124 | +0x0E4 / 228 | ULONG | Reference count (Win10+) |
| `DependentLoadFlags` | +0x080 / 128 | +0x0E8 / 232 | ULONG | Flags for dependent loads (Win10+) |
| `SigningLevel` | +0x084 / 132 | +0x0EC / 236 | UCHAR | Code signing level (Win10+) |

Note: Fields from `DdagNode` onward are Windows 8+ additions. Classic shellcode targets only the fields through `Flags` / `LoadCount`, which are stable across all modern versions.

### LIST_ENTRY reminder

Each `LIST_ENTRY` is two pointer-sized fields:

```
LIST_ENTRY (x86, 8 bytes):
  +0x000  Flink  DWORD  pointer to next entry's LIST_ENTRY
  +0x004  Blink  DWORD  pointer to previous entry's LIST_ENTRY

LIST_ENTRY (x64, 16 bytes):
  +0x000  Flink  QWORD  pointer to next entry's LIST_ENTRY
  +0x008  Blink  QWORD  pointer to previous entry's LIST_ENTRY
```

---

## The LIST_ENTRY Offset Delta Problem

This is the most common source of bugs in shellcode that walks the module list.

When you read `PEB_LDR_DATA.InInitializationOrderModuleList.Flink`, you get the address of the `InInitializationOrderLinks` field inside the first `LDR_DATA_TABLE_ENTRY`. You do NOT get a pointer to the start of that entry. The entry starts `0x010` bytes earlier.

The same applies to every subsequent `Flink` you follow — each gives you a pointer into the middle of an entry, at the specific `LIST_ENTRY` field for that list. You must subtract the list-specific offset delta to reach `entry_start`, and then add further offsets to reach any field you actually want.

### Offset Deltas for Each List (x86)

| List Name | LIST_ENTRY field in entry | Entry field offset | Delta to subtract from Flink to reach entry_start |
|---|---|---|---|
| `InLoadOrderModuleList` | `InLoadOrderLinks` | +0x000 | subtract **0x000** (no adjustment) |
| `InMemoryOrderModuleList` | `InMemoryOrderLinks` | +0x008 | subtract **0x008** |
| `InInitializationOrderModuleList` | `InInitializationOrderLinks` | +0x010 | subtract **0x010** |

After subtracting the delta, you have `entry_start`, and all the offsets in the structure table above apply normally.

### Shortcut: DllBase directly from Flink pointer

Since `DllBase` is always at `entry_start + 0x018`, and `entry_start = Flink - delta`, the offset from the raw Flink pointer to `DllBase` is:

- Via `InLoadOrderLinks` Flink: `[Flink + 0x018]` → DllBase
- Via `InMemoryOrderLinks` Flink: `[Flink + 0x010]` → DllBase  (0x018 - 0x008 = 0x010)
- Via `InInitializationOrderLinks` Flink: `[Flink + 0x008]` → DllBase  (0x018 - 0x010 = 0x008)

Most published shellcode walks `InInitializationOrderModuleList` and uses the `+0x008` shortcut for `DllBase`. This is correct and conventional.

### ASCII Memory Layout Diagram

The diagram below shows a single `LDR_DATA_TABLE_ENTRY` in memory on x86 with the three `LIST_ENTRY` anchors labeled and `DllBase` positioned relative to each:

```
  LDR_DATA_TABLE_ENTRY in memory (x86)
  =====================================

  entry_start (address X):
  ┌─────────────────────────────────────────────────────┐
  │  +0x000  InLoadOrderLinks.Flink         [4 bytes]   │ ← InLoadOrderModuleList Flink points HERE
  │  +0x004  InLoadOrderLinks.Blink         [4 bytes]   │
  ├─────────────────────────────────────────────────────┤
  │  +0x008  InMemoryOrderLinks.Flink       [4 bytes]   │ ← InMemoryOrderModuleList Flink points HERE
  │  +0x00C  InMemoryOrderLinks.Blink       [4 bytes]   │
  ├─────────────────────────────────────────────────────┤
  │  +0x010  InInitializationOrderLinks.Flink [4 bytes] │ ← InInitializationOrderModuleList Flink points HERE
  │  +0x014  InInitializationOrderLinks.Blink [4 bytes] │
  ├─────────────────────────────────────────────────────┤
  │  +0x018  DllBase                        [4 bytes]   │ ← target field
  │  +0x01C  EntryPoint                     [4 bytes]   │
  │  +0x020  SizeOfImage                    [4 bytes]   │
  ├─────────────────────────────────────────────────────┤
  │  +0x024  FullDllName.Length             [2 bytes]   │
  │  +0x026  FullDllName.MaximumLength      [2 bytes]   │
  │  +0x028  FullDllName.Buffer             [4 bytes]   │
  ├─────────────────────────────────────────────────────┤
  │  +0x02C  BaseDllName.Length             [2 bytes]   │
  │  +0x02E  BaseDllName.MaximumLength      [2 bytes]   │
  │  +0x030  BaseDllName.Buffer             [4 bytes]   │
  ├─────────────────────────────────────────────────────┤
  │  +0x034  Flags                          [4 bytes]   │
  │  +0x038  LoadCount                      [2 bytes]   │
  │  ...                                               │
  └─────────────────────────────────────────────────────┘

  Distance from each list anchor to DllBase:
    InLoadOrderLinks      → DllBase is +0x018 bytes ahead
    InMemoryOrderLinks    → DllBase is +0x010 bytes ahead (0x018 - 0x008)
    InInitOrderLinks      → DllBase is +0x008 bytes ahead (0x018 - 0x010)
```

---

## UNICODE_STRING Deep Dive

Both `FullDllName` and `BaseDllName` are `UNICODE_STRING` structures. Understanding the layout is essential because shellcode compares module names by reading raw bytes from the `Buffer`, not by calling any string comparison function.

### UNICODE_STRING Layout

```
_UNICODE_STRING (x86):
  +0x000  Length         USHORT  bytes currently used in the buffer (NOT character count, NOT including null)
  +0x002  MaximumLength  USHORT  total allocated buffer capacity in bytes
  +0x004  Buffer         PWSTR   pointer to UTF-16LE character array

_UNICODE_STRING (x64):
  +0x000  Length         USHORT  bytes currently used
  +0x002  MaximumLength  USHORT  total capacity
  +0x004  (2 bytes padding on x64 before next pointer-sized field)
  +0x008  Buffer         PWSTR   pointer to UTF-16LE character array
```

On x64, the `Buffer` pointer is at `+0x008` due to 8-byte pointer alignment, not `+0x004` as on x86.

### Length vs Character Count

`Length` counts **bytes**, not characters. UTF-16LE encodes every ASCII-range character as two bytes: the ASCII value followed by a zero byte. So:

```
"KERNEL32.DLL"  = 12 characters × 2 bytes = 24 bytes = 0x18  → Length = 0x18
"ntdll.dll"     =  9 characters × 2 bytes = 18 bytes = 0x12  → Length = 0x12
"kernel32.dll"  = 12 characters × 2 bytes = 24 bytes = 0x18  → Length = 0x18
"user32.dll"    = 10 characters × 2 bytes = 20 bytes = 0x14  → Length = 0x14
```

Note that on Windows XP and earlier the module name was stored as uppercase (`KERNEL32.DLL`). On Windows Vista and later it may be stored as mixed case (`kernel32.dll`). Reliable shellcode checks length first, then checks specific character positions rather than relying on exact case.

### The Buffer is NOT Null-Terminated

The Windows loader stores module names as `UNICODE_STRING` with `Length` tracking the end of the string. There is no null terminator at `Buffer[Length/2]`. This is why shellcode must use `Length` to know where the string ends, and why calling `wcscmp` or similar functions is unsafe — they would scan past the end of the valid data.

### Why Not Just Use wcscmp

Even if `wcscmp` were available in shellcode:
1. Null termination is not guaranteed (see above)
2. Case sensitivity varies by Windows version and call site
3. wcscmp would require resolving the function address first, creating a circular dependency

The canonical shellcode approach is:
1. Check `BaseDllName.Length` against the expected byte count
2. Check the first 4 or 8 bytes of `Buffer` against known UTF-16LE character patterns
3. Optionally check a few more characters if uniqueness requires it

### UTF-16LE Character Encoding

In UTF-16LE, each ASCII character `c` is stored as two bytes: `c, 0x00`. In memory (little-endian x86/x64), reading a DWORD from the start of a UTF-16LE string reads two characters at once:

```
"KE" in UTF-16LE in memory:  4B 00 45 00
                              K  \0  E  \0
As a DWORD (little-endian): 0x0045004B

"RN" in UTF-16LE in memory:  52 00 4E 00
As a DWORD: 0x004E0052

"EL" in UTF-16LE in memory:  45 00 4C 00
As a DWORD: 0x004C0045

First 8 bytes of "KERNEL32.DLL":
  K=4B  E=45  R=52  N=4E  E=45  L=4C  3=33  2=32
  Memory: 4B 00 45 00 52 00 4E 00  45 00 4C 00 33 00 32 00
  DWORD at +0: 0x0045004B  ("KE")
  DWORD at +4: 0x004E0052  ("RN")

First 8 bytes of "ntdll.dll":
  n=6E  t=74  d=64  l=6C  l=6C  .=2E  d=64  l=6C
  Memory: 6E 00 74 00 64 00 6C 00  6C 00 2E 00 64 00 6C 00
  DWORD at +0: 0x0074006E  ("nt")
  DWORD at +4: 0x006C0064  ("dl")
```

---

## Assembly Walkthrough: Finding kernel32.dll via InInitializationOrderModuleList

This is the classic technique used in nearly all x86 shellcode. The walk uses the initialization-order list because `kernel32.dll` is reliably among the first entries (it must be initialized before most other DLLs), and the offset arithmetic makes `DllBase` easy to reach at `[ESI + 0x008]`.

### Offset Arithmetic Reference (x86)

When `ESI` points to the `InInitializationOrderLinks` field of an entry (i.e., `ESI` is the raw `Flink` value from following the list):

```
entry_start   = ESI - 0x010   (InInitializationOrderLinks is at entry_start+0x010)
DllBase       = ESI + 0x008   (entry_start+0x018, delta = 0x018-0x010 = 0x008)
BaseDllName   = ESI + 0x01C   (entry_start+0x02C, delta = 0x02C-0x010 = 0x01C)
  .Length     = ESI + 0x01C   (same offset — .Length is first field of UNICODE_STRING)
  .Buffer     = ESI + 0x020   (entry_start+0x030, delta = 0x030-0x010 = 0x020)
```

### Complete Annotated Assembly

```nasm
; ============================================================
; find_kernel32:
;   Returns: EBX = kernel32.dll DllBase (ImageBase)
;   Clobbers: EAX, ECX, ESI
;   Assumes: PIC-style access to FS segment
; ============================================================

find_kernel32:
    ; Step 1: Get PEB address from TEB.ProcessEnvironmentBlock
    ; TEB is at FS:[0x00] (the TEB base is FS segment base)
    ; TEB.ProcessEnvironmentBlock is at TEB+0x030
    mov  eax, dword [fs:0x30]       ; EAX = PEB*

    ; Step 2: Get PEB_LDR_DATA* from PEB.Ldr (at PEB+0x00C)
    mov  eax, dword [eax + 0x0C]    ; EAX = PEB_LDR_DATA*

    ; Step 3: Get first Flink from InInitializationOrderModuleList
    ; PEB_LDR_DATA.InInitializationOrderModuleList is at PEB_LDR_DATA+0x01C
    ; .Flink is the first DWORD of that LIST_ENTRY
    mov  esi, dword [eax + 0x1C]    ; ESI = first Flink (points into first LDR entry's
                                    ;       InInitializationOrderLinks field)

    ; -------------------------------------------------------
    ; Loop head: ESI = current Flink pointing to
    ;            InInitializationOrderLinks of current entry
    ; -------------------------------------------------------
.loop:
    ; Sentinel check: the list is circular. The last entry's Flink
    ; points back to InInitializationOrderModuleList inside PEB_LDR_DATA.
    ; That address is PEB_LDR_DATA + 0x01C. We stored PEB_LDR_DATA in EAX.
    ; Check if we have looped all the way back to the list head.
    ; Re-read EAX was clobbered if we branch here from below — keep EAX intact.
    ; (In this version EAX still holds PEB_LDR_DATA*.)
    lea  ecx, [eax + 0x1C]          ; ECX = &PEB_LDR_DATA.InInitializationOrderModuleList
    cmp  esi, ecx                   ; did Flink wrap back to list head?
    je   .not_found                 ; yes → kernel32 not found (should never happen in normal process)

    ; -------------------------------------------------------
    ; Step 4: Read BaseDllName.Length
    ; BaseDllName.Length is at [entry_start + 0x02C]
    ; entry_start = ESI - 0x010
    ; So: BaseDllName.Length = [(ESI - 0x010) + 0x02C] = [ESI + 0x01C]
    ; -------------------------------------------------------
    movzx ecx, word [esi + 0x1C]    ; ECX = BaseDllName.Length (USHORT, zero-extend)

    ; kernel32.dll = 12 characters * 2 bytes/char = 0x18 bytes
    cmp  ecx, 0x18                  ; is name length 24 bytes?
    jne  .advance                   ; no → skip this entry

    ; -------------------------------------------------------
    ; Step 5: Read BaseDllName.Buffer pointer
    ; BaseDllName.Buffer is at [entry_start + 0x030]
    ; From ESI: [ESI + 0x020]
    ; -------------------------------------------------------
    mov  ecx, dword [esi + 0x20]    ; ECX = BaseDllName.Buffer (PWSTR, pointer to UTF-16LE)

    ; -------------------------------------------------------
    ; Step 6: Check first 4 bytes of Buffer == "KE" in UTF-16LE
    ; 'K' = 0x4B, 'E' = 0x45
    ; In memory (little-endian): 4B 00 45 00
    ; As DWORD: 0x0045004B
    ; -------------------------------------------------------
    mov  eax, dword [ecx]           ; EAX = first 4 bytes of module name string
    cmp  eax, 0x0045004B            ; "KE" in UTF-16LE?
    jne  .advance_restore           ; no → not kernel32, restore EAX and keep looping

    ; -------------------------------------------------------
    ; Step 7: Check next 4 bytes == "RN" in UTF-16LE
    ; 'R' = 0x52, 'N' = 0x4E
    ; As DWORD: 0x004E0052
    ; This extra check reduces false positives (e.g., "KERNEL64" hypothetical)
    ; -------------------------------------------------------
    mov  eax, dword [ecx + 4]       ; EAX = next 4 bytes ("RN" if kernel32)
    cmp  eax, 0x004E0052            ; "RN" in UTF-16LE?
    jne  .advance_restore           ; no → not kernel32

    ; -------------------------------------------------------
    ; Step 8: Match confirmed — load DllBase
    ; DllBase is at [entry_start + 0x018]
    ; From ESI: [ESI + 0x008]
    ; -------------------------------------------------------
    mov  ebx, dword [esi + 0x08]    ; EBX = kernel32.dll ImageBase (DllBase)
    test ebx, ebx                   ; sanity: DllBase must be non-zero
    jz   .advance_restore           ; zero base → corrupted entry, keep looking

    ; Found and loaded. EBX = kernel32.dll base. Done.
    ; Restore EAX to PEB_LDR_DATA* before returning (caller may need it)
    mov  eax, dword [fs:0x30]
    mov  eax, dword [eax + 0x0C]
    ret

    ; -------------------------------------------------------
    ; Advance: move to next entry in the list
    ; ESI = [ESI] reads Flink of the current InInitializationOrderLinks
    ; which points to InInitializationOrderLinks of the NEXT entry
    ; -------------------------------------------------------
.advance_restore:
    ; EAX was clobbered by the string comparisons above — restore PEB_LDR_DATA*
    mov  eax, dword [fs:0x30]
    mov  eax, dword [eax + 0x0C]
    ; fall through to .advance

.advance:
    mov  esi, dword [esi]           ; ESI = InInitializationOrderLinks.Flink of next entry
    jmp  .loop

.not_found:
    xor  ebx, ebx                   ; EBX = 0 signals failure
    ret
```

### Alternative: PIC-friendly version without re-reading PEB in the loop

For shellcode that must minimize size or avoid repeated PEB accesses, save `PEB_LDR_DATA*` on the stack before entering the loop and restore it only for the sentinel check. The above version is optimized for clarity over size.

---

## Walking InMemoryOrderModuleList (x86)

For completeness, here is the offset arithmetic when walking the memory-order list instead:

When `ESI` points to `InMemoryOrderLinks` (raw Flink from `InMemoryOrderModuleList`):

```
entry_start   = ESI - 0x008   (InMemoryOrderLinks is at entry_start+0x008)
DllBase       = ESI + 0x010   (entry_start+0x018, delta = 0x018-0x008 = 0x010)
BaseDllName   = ESI + 0x024   (entry_start+0x02C, delta = 0x02C-0x008 = 0x024)
  .Length     = ESI + 0x024
  .Buffer     = ESI + 0x028   (entry_start+0x030, delta = 0x030-0x008 = 0x028)
```

Sentinel: last Flink points back to `PEB_LDR_DATA.InMemoryOrderModuleList` at `PEB_LDR_DATA + 0x014`.

---

## Walking InLoadOrderModuleList (x86)

When `ESI` points to `InLoadOrderLinks` (raw Flink from `InLoadOrderModuleList`), `InLoadOrderLinks` is at `entry_start + 0x000`, so no adjustment is needed. The raw Flink IS the entry start:

```
entry_start   = ESI             (no subtraction needed)
DllBase       = ESI + 0x018
BaseDllName   = ESI + 0x02C
  .Length     = ESI + 0x02C
  .Buffer     = ESI + 0x030
```

Sentinel: last Flink points back to `PEB_LDR_DATA.InLoadOrderModuleList` at `PEB_LDR_DATA + 0x00C`.

This is the simplest list to walk mathematically, but shellcode conventionally uses `InInitializationOrderModuleList` for historical reasons and because the first entry in the load-order list is the main EXE (not a DLL), which must be skipped.

---

## Flags Bitfield

The `Flags` field at `+0x034` (x86) is a bitmask maintained by the loader. Most bits are internal loader state, but a few are useful for shellcode and anti-analysis work:

| Flag Value | Name | Meaning |
|---|---|---|
| 0x00000001 | `LDRP_PACKAGED_BINARY` | Module is part of an AppX package |
| 0x00000002 | `LDRP_STATIC_LINK` | Module is statically linked (rare) |
| 0x00000004 | `LDRP_IMAGE_DLL` | Module is a DLL (as opposed to EXE) |
| 0x00000008 | `LDRP_LOAD_IN_PROGRESS` | Module is currently being loaded |
| 0x00000010 | `LDRP_UNLOAD_IN_PROGRESS` | Module is currently being unloaded |
| 0x00000020 | `LDRP_ENTRY_PROCESSED` | Loader has processed the entry |
| 0x00000040 | `LDRP_PROTECT_DELAY_LOAD` | Delay-load protection active |
| 0x00000080 | `LDRP_PROCESS_STATIC_IMPORT` | Static imports being processed |
| 0x00000200 | `LDRP_IN_LEGACY_LISTS` | Entry is in the legacy module list |
| 0x00000400 | `LDRP_IN_INDEXES` | Entry is in loader index structures |
| 0x00000800 | `LDRP_SHIM_DLL` | Module is a shim DLL |
| 0x00001000 | `LDRP_ENTRY_PROCESSED` | `DllMain` has been called (older naming) |
| 0x00004000 | `LDRP_PROCESS_ATTACH_CALLED` | `DLL_PROCESS_ATTACH` notification was sent |
| 0x00008000 | `LDRP_PROCESS_ATTACH_FAILED` | `DLL_PROCESS_ATTACH` returned FALSE |
| 0x00010000 | `LDRP_COR_DEFERRED_VALIDATE` | .NET validation deferred |
| 0x00020000 | `LDRP_COR_IMAGE` | Module is a managed (.NET) assembly |
| 0x00040000 | `LDRP_DONT_RELOCATE` | Module must not be relocated |
| 0x00080000 | `LDRP_COR_IL_ONLY` | Module is pure IL (.NET) |
| 0x00100000 | `LDRP_CHPE_IMAGE` | ARM64X/CHPE image (ARM64 on Windows 10) |
| 0x00200000 | `LDRP_CHPE_IMAGE_NATIVE` | Native CHPE image |
| 0x01000000 | `LDRP_REDIRECTED` | Module has been redirected |
| 0x20000000 | `LDRP_COMPAT_DATABASE_PROCESSED` | Compatibility database processed |

### Exploit-relevant flag checks

```nasm
; Check if module is a DLL (not the main EXE)
mov  eax, dword [esi - 0x10 + 0x34]   ; load Flags from entry_start+0x034
test eax, 0x00000004                   ; LDRP_IMAGE_DLL
jz   .skip                             ; not a DLL, skip

; Check if module is .NET/managed
test eax, 0x00020000                   ; LDRP_COR_IMAGE
jnz  .managed_module                   ; flag it and move on
```

---

## WinDbg Verification

### Dumping the structure definition

```
0:000> dt ntdll!_LDR_DATA_TABLE_ENTRY
   +0x000 InLoadOrderLinks         : _LIST_ENTRY
   +0x008 InMemoryOrderLinks       : _LIST_ENTRY
   +0x010 InInitializationOrderLinks : _LIST_ENTRY
   +0x018 DllBase                  : Ptr32 Void
   +0x01c EntryPoint               : Ptr32 Void
   +0x020 SizeOfImage              : Uint4B
   +0x024 FullDllName              : _UNICODE_STRING
   +0x02c BaseDllName              : _UNICODE_STRING
   +0x034 FlagGroup                : [4] UChar
   +0x034 Flags                    : Uint4B
   +0x038 ObsoleteLoadCount        : Uint2B
   +0x03a TlsIndex                 : Uint2B
   +0x03c HashLinks                : _LIST_ENTRY
   +0x044 TimeDateStamp            : Uint4B
   ...
```

### Walking the list from the PEB

```
0:000> dt ntdll!_PEB_LDR_DATA poi(@$peb+0xc)
   +0x000 Length                          : 0x30
   +0x004 Initialized                     : 0x1 ''
   +0x008 SsHandle                        : (null)
   +0x00c InLoadOrderModuleList           : _LIST_ENTRY [ 0x2b7a20 - 0x2b9e40 ]
   +0x014 InMemoryOrderModuleList         : _LIST_ENTRY [ 0x2b7a28 - 0x2b9e48 ]
   +0x01c InInitializationOrderModuleList : _LIST_ENTRY [ 0x2b7a30 - 0x2b9e18 ]
   +0x024 EntryInProgress                 : (null)

; The InInitializationOrderModuleList Flink is 0x2b7a30.
; That points to InInitializationOrderLinks of the first real entry.
; entry_start = 0x2b7a30 - 0x10 = 0x2b7a20

0:000> dt ntdll!_LDR_DATA_TABLE_ENTRY (0x2b7a30-0x10)
   +0x000 InLoadOrderLinks         : _LIST_ENTRY [ 0x2b9e30 - 0x77a94d18 ]
   +0x008 InMemoryOrderLinks       : _LIST_ENTRY [ 0x2b9e38 - 0x77a94d20 ]
   +0x010 InInitializationOrderLinks : _LIST_ENTRY [ 0x2b7a50 - 0x77a95afc ]
   +0x018 DllBase                  : 0x77a60000 Void   ← ntdll.dll ImageBase
   +0x01c EntryPoint               : 0x77a9b4e0 Void
   +0x020 SizeOfImage              : 0x150000
   +0x024 FullDllName              : _UNICODE_STRING "C:\Windows\SYSTEM32\ntdll.dll"
   +0x02c BaseDllName              : _UNICODE_STRING "ntdll.dll"
   +0x034 Flags                    : 0xa2cc

; Follow to next entry via InInitializationOrderLinks.Flink = 0x2b7a50
; entry_start = 0x2b7a50 - 0x10 = 0x2b7a40

0:000> dt ntdll!_LDR_DATA_TABLE_ENTRY (0x2b7a50-0x10)
   +0x018 DllBase                  : 0x755d0000 Void   ← kernel32.dll ImageBase
   +0x02c BaseDllName              : _UNICODE_STRING "KERNEL32.DLL"

; Verify DllBase directly from the raw Flink offset shortcut
0:000> dd 0x2b7a50+0x08 L1
0x2b7a58  755d0000    ← correct: kernel32.dll DllBase at [InInitOrderFlink + 0x08]
```

### Displaying BaseDllName.Buffer contents as Unicode

```
0:000> du poi(0x2b7a50-0x10+0x030)
00400068  "KERNEL32.DLL"

; Or using UNICODE_STRING dump command:
0:000> du poi((0x2b7a50-0x10)+0x02c+0x04)
00400068  "KERNEL32.DLL"
```

### Checking Flags

```
0:000> .formats poi(0x2b7a50-0x10+0x034)
Evaluate expression:
  Hex:     00004000
  Binary:  0000 0000 0000 0000 0100 0000 0000 0000

; Bit 0x4000 = LDRP_PROCESS_ATTACH_CALLED: DllMain(DLL_PROCESS_ATTACH) was called
```

### Script to walk all entries

```
0:000> .foreach /pS 1 /ps 1 ( addr { dd poi(@$peb+0xc)+0x1c L1 } ) { .if (addr != poi(@$peb+0xc)+0x1c) { du poi(addr-0x10+0x030) } }
```

This one-liner walks `InInitializationOrderModuleList` and prints each `BaseDllName.Buffer`.

---

## x86 vs x64 Offset Summary

Because pointer fields double from 4 bytes to 8 bytes on x64, every pointer-containing field shifts:

| Field | x86 Offset | x64 Offset | Size x86 | Size x64 |
|---|---|---|---|---|
| `InLoadOrderLinks` | +0x000 | +0x000 | 8 | 16 |
| `InMemoryOrderLinks` | +0x008 | +0x010 | 8 | 16 |
| `InInitializationOrderLinks` | +0x010 | +0x020 | 8 | 16 |
| `DllBase` | +0x018 | +0x030 | 4 | 8 |
| `EntryPoint` | +0x01C | +0x038 | 4 | 8 |
| `SizeOfImage` | +0x020 | +0x040 | 4 | 4 |
| `FullDllName` | +0x024 | +0x048 | 8 | 16 |
| `BaseDllName` | +0x02C | +0x058 | 8 | 16 |
| `Flags` | +0x034 | +0x068 | 4 | 4 |
| `LoadCount` | +0x038 | +0x06C | 2 | 2 |

On x64, `UNICODE_STRING.Buffer` is at `+0x008` within the struct (not `+0x004`) due to pointer alignment padding. When walking `InInitializationOrderModuleList` on x64:

```
entry_start   = Flink - 0x020   (InInitializationOrderLinks at +0x020 on x64)
DllBase       = Flink + 0x010   (entry_start+0x030, delta = 0x030-0x020 = 0x010)
BaseDllName   = Flink + 0x038   (entry_start+0x058, delta = 0x058-0x020 = 0x038)
  .Length     = Flink + 0x038
  .Buffer     = Flink + 0x040   (entry_start+0x060, delta = 0x060-0x020 = 0x040)
```

---

## Common Mistakes

### 1. Using the raw Flink as the entry pointer without applying the delta

```nasm
; WRONG — using InInitOrder Flink directly as entry_start
mov  esi, dword [eax + 0x1C]    ; ESI = Flink (points to InInitOrderLinks, not entry start)
mov  ebx, dword [esi + 0x18]    ; WRONG: this reads entry_start+0x028, not DllBase
                                 ; DllBase is at entry_start+0x018 = Flink+0x008, NOT Flink+0x018

; CORRECT
mov  ebx, dword [esi + 0x08]    ; DllBase is at Flink + 0x008 when walking InInitOrder list
```

### 2. Comparing UTF-16 names with ASCII byte values

```nasm
; WRONG — comparing 'K' as a byte (0x4B), ignoring the zero padding
cmp  byte [ecx], 0x4B           ; tests only the first byte of 'K' (the 4B)
                                 ; this would pass for any UTF-16LE string starting with K

; WRONG — treating the first 4 bytes as ASCII "KERN"
cmp  dword [ecx], 0x4E52454B    ; "NREK" in little-endian... no, "KERN"
                                 ; but the actual memory is 4B 00 45 00, not 4B 45 52 4E

; CORRECT — compare first DWORD as UTF-16LE "KE"
cmp  dword [ecx], 0x0045004B    ; memory: 4B 00 45 00 = "K\0E\0"
```

### 3. Not checking for the circular list sentinel

The list is circular. When you reach the last real entry, its `InInitializationOrderLinks.Flink` points back to `PEB_LDR_DATA.InInitializationOrderModuleList` (the list head), not to NULL. If you loop without checking for this sentinel, you will walk back into `PEB_LDR_DATA` and interpret its fields as if they were `LDR_DATA_TABLE_ENTRY` fields — reading garbage as `DllBase`, potentially faulting or returning wrong addresses.

```nasm
; WRONG — loops forever or faults if target DLL is not found
.loop:
    mov  ebx, dword [esi + 0x08]
    ; ... check name, advance ...
    mov  esi, dword [esi]
    jmp  .loop

; CORRECT — check sentinel before each iteration
.loop:
    lea  ecx, [eax + 0x1C]          ; ECX = address of InInitOrderModuleList in PEB_LDR_DATA
    cmp  esi, ecx
    je   .not_found                  ; ESI wrapped back to list head: all entries exhausted
    ; ... check name, advance, repeat ...
```

### 4. Assuming kernel32 is always the second entry in InInitializationOrderList

On classic Windows XP and early Vista, `InInitializationOrderModuleList` starts with ntdll.dll, then kernel32.dll (or kernelbase.dll from Win7 onward). Some shellcode skips the first entry unconditionally and treats the second as kernel32. This breaks when:

- Windows 10 with SysWOW64: additional compatibility DLLs may appear before kernel32
- Wine/proton: list order differs from Windows
- Process hollowing or manual DLL loading: attacker-controlled entries may be inserted

Always compare the name rather than relying on position.

### 5. Using BaseDllName.Length alone as the only check

The string "kernel32.dll" is 12 characters (24 bytes). Other DLL names that are also 12 characters long exist (e.g., hypothetical "KERNELXY.DLL"). Always follow the length check with at least one character comparison.

### 6. Not handling the case where DllBase is NULL

A partially initialized `LDR_DATA_TABLE_ENTRY` (e.g., one that is currently being loaded when `LDRP_LOAD_IN_PROGRESS` is set) may have `DllBase = NULL`. Blindly returning a NULL base as kernel32 will cause the next stage of shellcode to crash. Check that `DllBase` is non-zero before accepting the result.

---

## Defensive Caveats and EDR Implications

### Module list integrity monitoring

EDR products and endpoint agents regularly scan all three module lists and compare them to the list of mapped virtual address regions returned by `NtQueryVirtualMemory`. A DLL that is loaded but has had its `LDR_DATA_TABLE_ENTRY` unlinked (manually removed from all three lists) will appear as an anonymous executable region — a strong signal of stealth loading or reflective DLL injection.

### Hook placement

`ntdll!LdrLoadDll` and `ntdll!LdrGetProcedureAddress` are the two loader functions most frequently hooked by EDR user-mode components. Hooks are placed by overwriting the first few bytes of the function with a jump to the EDR's monitoring code. Shellcode that bypasses these hooks by calling `NtMapViewOfSection` directly and constructing its own import table will load code that is not represented in the module list — detectable by the region/list comparison above.

### TimeDateStamp as a fingerprint

The `TimeDateStamp` field at `+0x044` (x86) stores the PE header's `TimeDateStamp`. Some hardened systems verify that this matches the timestamp in the actual mapped PE header. Manually patched or compiled-from-source DLLs with zeroed timestamps can be flagged.

### Reflective loaders

A reflective DLL loader (e.g., `ReflectiveDLLInjection`) maps and links a DLL without going through the loader, so it creates no `LDR_DATA_TABLE_ENTRY`. The DLL's exports work, `GetModuleHandle` returns NULL for it, and module-enumeration APIs (`EnumProcessModules`, `CreateToolhelp32Snapshot`) do not list it. Post-exploitation frameworks rely on this behavior; EDR products counter it by scanning all executable virtual regions.

---

## Version Notes

- **Windows XP (x86):** Classic layout as described above. `InInitializationOrderModuleList` order: ntdll → kernel32 → ...
- **Windows Vista/7:** `KernelBase.dll` introduced as a refactored kernel32. Some APIs moved there. The list now contains `KernelBase.dll` between ntdll and kernel32 in some init sequences.
- **Windows 8:** `DdagNode`, `NodeModuleLink`, and related fields added for the new dependency-aware loader (DDAG = DLL Dependency Acyclic Graph). Old fields preserved at same offsets.
- **Windows 10:** Additional fields (`ReferenceCount`, `DependentLoadFlags`, `SigningLevel`) appended. Core fields unchanged. 32-bit processes running under WoW64 use the same x86 offsets — the WoW64 process has its own PEB and loader state.
- **Windows 11:** No structural changes to the core fields. ASLR improvements affect where `PEB_LDR_DATA` and entries are allocated, but not their internal layout.

---

## Related Structures

- `PEB` — contains `Ldr` field pointing to `PEB_LDR_DATA`; see `PEB.md`
- `PEB_LDR_DATA` — contains the three list heads; see `PEB_LDR_DATA.md`
- `TEB` — contains `ProcessEnvironmentBlock` field; entry point for shellcode; see `TEB.md`
- `UNICODE_STRING` — used by `FullDllName` and `BaseDllName`
- `IMAGE_NT_HEADERS` — PE header; `DllBase` points to this in memory
- `IMAGE_EXPORT_DIRECTORY` — walked after `DllBase` is found to resolve function addresses
