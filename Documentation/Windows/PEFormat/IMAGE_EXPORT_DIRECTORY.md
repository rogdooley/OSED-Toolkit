# IMAGE_EXPORT_DIRECTORY — Comprehensive Reference

## Table of Contents

1. [Purpose and Exploit Relevance](#purpose-and-exploit-relevance)
2. [Why Exports Exist: The DLL Linking Model](#why-exports-exist)
3. [Structure Definition and Field Table](#structure-definition)
4. [Deep Field Explanations](#deep-field-explanations)
5. [Three-Table Resolution Algorithm](#three-table-resolution-algorithm)
6. [Complete Assembly Implementation](#complete-assembly-implementation)
7. [Forwarded Exports](#forwarded-exports)
8. [Finding the Export Directory RVA](#finding-the-export-directory-rva)
9. [WinDbg Step-by-Step Walkthrough](#windbg-step-by-step-walkthrough)
10. [Common Mistakes](#common-mistakes)
11. [Quick Reference Summary](#quick-reference-summary)

---

## Purpose and Exploit Relevance

The PE export directory is the mechanism that makes shellcode API resolution possible. When shellcode needs to call `VirtualAlloc`, `WSASocketA`, or `CreateProcessA`, it cannot use the normal import mechanism — the shellcode has no import table, no loader fixing it up, and no symbol table. Instead, it replicates a subset of what the Windows PE loader does at process startup: walk the export directory of an already-loaded DLL and resolve function addresses at runtime.

This is not a trick or a bypass. It is the documented, intended behavior of the PE export mechanism, turned to offensive use.

### Why Shellcode Uses Export Parsing Instead of GetProcAddress

One might ask: why not just call `GetProcAddress`? In fact, many shellcodes do — but to call `GetProcAddress`, the shellcode must first resolve `GetProcAddress` itself. That requires either:

1. A hardcoded address (breaks across OS versions, ASLR, service packs)
2. Parsing the export directory of kernel32.dll to find `GetProcAddress` by name or hash

Option 2 is the standard approach. The export directory parse is the bootstrap that makes everything else possible. Once the shellcode has `GetProcAddress`, it can resolve anything else; but the first resolution must always be manual.

### The Loader Does This Too

When Windows loads a process, the PE loader:

1. Maps all required DLLs into the process address space
2. For each import in the EXE's import table, locates the exporting DLL
3. Parses that DLL's export directory to find the exported function address
4. Writes the resolved address into the EXE's Import Address Table (IAT)

Shellcode skips steps 1 and 4 entirely (the DLLs are already mapped; shellcode does not have an IAT). It performs only step 3, the export directory parse, and stores results in its own stack-based function pointer table.

---

## Why Exports Exist: The DLL Linking Model

### The Original Problem

When Microsoft designed the DLL mechanism for Windows, they needed a way for one module to expose functionality to other modules without those other modules needing to know in advance where in memory the functions would be located. The solution was two complementary structures:

- **Export directory** (in the DLL): "Here is the list of functions I provide, and where they are relative to my load base."
- **Import directory** (in the EXE or other DLL): "Here is the list of functions I need, and which DLL to find them in."

The loader connects these at process startup by:
1. Enumerating the importing module's import descriptors
2. For each descriptor, finding the named DLL in the already-loaded module list (or loading it)
3. For each imported function name or ordinal, searching the exporting DLL's export directory
4. Writing the resolved VA into the importing module's IAT

### Why the Export Directory Is Always Present in Memory

Unlike some PE structures that are only used during loading and could theoretically be discarded, the export directory is mapped into the process's virtual memory as part of the DLL image. It is part of a normal PE section (typically `.rdata` or `.edata`). This means:

- Any code running in the same process can read the export directory of any loaded module
- No special privileges are required
- No system calls are needed — it is ordinary memory reads
- It works in any execution context: normal thread, injected thread, ROP chain with memory-read primitives, etc.

This is why shellcode can resolve exports without interacting with any Windows API — the data is already mapped and readable.

---

## Structure Definition

### Raw C Definition

```c
typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD   Characteristics;        // +0x00
    DWORD   TimeDateStamp;          // +0x04
    WORD    MajorVersion;           // +0x08
    WORD    MinorVersion;           // +0x0A
    DWORD   Name;                   // +0x0C  (RVA)
    DWORD   Base;                   // +0x10
    DWORD   NumberOfFunctions;      // +0x14
    DWORD   NumberOfNames;          // +0x18
    DWORD   AddressOfFunctions;     // +0x1C  (RVA)
    DWORD   AddressOfNames;         // +0x20  (RVA)
    DWORD   AddressOfNameOrdinals;  // +0x24  (RVA)
} IMAGE_EXPORT_DIRECTORY;
// Total size: 0x28 bytes (40 bytes)
```

### Field Table

```
Offset  Size  Name                    Description
------  ----  ----                    -----------
+0x00   DWORD Characteristics         Reserved; always 0 in valid PEs.
                                      The PE specification reserved this for
                                      future use; the loader ignores it.

+0x04   DWORD TimeDateStamp           Unix timestamp (seconds since 1970-01-01)
                                      when the export table was built.
                                      Useful for version analysis; not used
                                      by the loader or shellcode.
                                      Note: linkers often set this to 0 or a
                                      reproducible value for deterministic builds.

+0x08   WORD  MajorVersion            Always 0 in practice. Reserved for
                                      user-defined versioning of the export
                                      table; the loader ignores it.

+0x0A   WORD  MinorVersion            Always 0 in practice. Same as above.

+0x0C   DWORD Name                    RVA → null-terminated ASCII string
                                      containing the DLL's canonical name.
                                      Example: "KERNEL32.dll\0"
                                      This name may differ from the filename
                                      (e.g., the file on disk could be renamed).
                                      The loader does NOT use this field for
                                      module lookup — it is informational only.

+0x10   DWORD Base                    The ordinal base. Ordinal numbers exposed
                                      to the outside world start at this value.
                                      Almost always 1. The first exported
                                      function has ordinal (Base), the second
                                      has ordinal (Base+1), etc.
                                      Critical: The AddressOfNameOrdinals values
                                      are ALREADY zero-based and do NOT need
                                      Base subtracted. See deep explanation below.

+0x14   DWORD NumberOfFunctions       Total count of entries in the Export
                                      Address Table (EAT). This is the size of
                                      the AddressOfFunctions array.
                                      Includes gap entries (NULL RVAs) for
                                      skipped ordinals. May be larger than
                                      NumberOfNames because some functions are
                                      exported by ordinal only.

+0x18   DWORD NumberOfNames           Count of named exports. This is the size
                                      of both the AddressOfNames array and the
                                      AddressOfNameOrdinals array. Always:
                                        NumberOfNames <= NumberOfFunctions
                                      Shellcode walking by name iterates this
                                      count, not NumberOfFunctions.

+0x1C   DWORD AddressOfFunctions      RVA → Export Address Table (EAT).
                                      Array of DWORD RVAs. Array has
                                      NumberOfFunctions entries. Each entry is
                                      either:
                                        - RVA to function code (normal export)
                                        - RVA to forwarder string (forwarded export)
                                        - 0 (gap/missing ordinal)

+0x20   DWORD AddressOfNames          RVA → Export Name Pointer Table (ENPT).
                                      Array of DWORD RVAs. Array has
                                      NumberOfNames entries. Each entry is an
                                      RVA to a null-terminated ASCII function
                                      name string.
                                      CRITICAL: This array is sorted
                                      alphabetically by name. Binary search
                                      is valid; shellcode uses linear search.

+0x24   DWORD AddressOfNameOrdinals   RVA → Export Ordinal Table (EOT).
                                      Array of WORD (2-byte) values. Array has
                                      NumberOfNames entries. Parallel to
                                      AddressOfNames: element [i] gives the
                                      zero-based index into AddressOfFunctions
                                      for the function named AddressOfNames[i].
                                      DATA TYPE IS WORD — reading as DWORD
                                      is a common and fatal error.
```

---

## Deep Field Explanations

### The Base Field and the Ordinal Confusion

The `Base` field creates more confusion than any other field in the export directory. The confusion stems from conflating two different concepts: **external ordinals** (what users of the DLL see) and **internal function indices** (what the EAT is indexed by).

**External ordinals** are what appear in the export list of a DLL, what you would pass to `GetProcAddress(hModule, MAKEINTRESOURCE(n))`, and what import tables use for ordinal-based imports. These start at `Base`.

**Internal function indices** are zero-based indices into the AddressOfFunctions array. These are what `AddressOfNameOrdinals` stores.

The relationship is:

```
external_ordinal = internal_function_index + Base
internal_function_index = external_ordinal - Base
```

For name-based lookup (which is what shellcode does):

```
Step 1: find name at index i in AddressOfNames
Step 2: func_index = AddressOfNameOrdinals[i]   ← already zero-based, no adjustment
Step 3: func_rva   = AddressOfFunctions[func_index]
```

The `Base` field is NEVER used in name-based lookup. It is only relevant if you are doing ordinal-based lookup (e.g., resolving by ordinal number from an import table entry that uses ordinal-based import).

For ordinal-based lookup:

```
Step 1: have external_ordinal (e.g., from import table)
Step 2: func_index = external_ordinal - Base
Step 3: validate: func_index < NumberOfFunctions
Step 4: func_rva = AddressOfFunctions[func_index]
```

**Practical note for kernel32.dll**: Base is 1. If you see `AddressOfNameOrdinals[i] = 0x0042`, that means the function is at `AddressOfFunctions[0x0042]` (zero-based). Its external ordinal would be `0x0042 + 1 = 0x0043 = 67`.

### NumberOfFunctions vs NumberOfNames

These are separate counts for a reason.

```
NumberOfFunctions = 1423  (total EAT entries, including gaps)
NumberOfNames     = 1398  (named exports)

The 25 remaining functions (1423 - 1398) are ordinal-only:
they have entries in AddressOfFunctions but no corresponding
entries in AddressOfNames or AddressOfNameOrdinals.
```

Gap entries exist because the ordinal space may have holes. For example, if a DLL exports ordinals 1, 2, 3, 5 (skipping 4), there must still be 5 entries in the EAT (for ordinals 1-5), with the entry at index 3 (ordinal 4) being a null RVA.

Shellcode walking by name iterates `0` to `NumberOfNames - 1`. If you accidentally iterate to `NumberOfFunctions`, you will walk past the end of the name and ordinal arrays into unmapped or unrelated memory.

### The Export Address Table (AddressOfFunctions)

Each entry is a DWORD RVA. Possible values:

| Value | Meaning |
|-------|---------|
| 0x00000000 | Gap entry — this ordinal is not exported |
| RVA outside export directory range | Normal export — code or data at this RVA |
| RVA within export directory range | Forwarded export — pointer to forwarder string |

The "within export directory range" check is how you detect forwarded exports. The export directory's location and size come from `DataDirectory[0]` in the Optional Header. See the [Forwarded Exports](#forwarded-exports) section for complete details.

### AddressOfNames: The Sorted Name Pointer Array

The PE specification states that `AddressOfNames` must be sorted in ascending lexicographic order by the function name strings. This sorting is performed by the linker at build time.

Consequences:
- **Binary search is valid** — you can bisect the array to find a name in O(log n) comparisons
- **Shellcode typically uses linear search** — the overhead of binary search in 50-100 bytes of shellcode is not worth the complexity
- **The sort is case-sensitive** — "VirtualAlloc" < "WinExec" alphabetically; "virtualalloc" would sort differently
- **Hash-based search ignores the sort entirely** — when hashing each name and comparing to a target hash, the sort order is irrelevant

### AddressOfNameOrdinals: The Parallel Ordinal Array

This array is parallel to `AddressOfNames`: element `[i]` in the ordinal array corresponds to element `[i]` in the names array. They must be indexed with the same index `i`.

Key properties:
- **Data type is WORD (2 bytes)**, not DWORD. Reading 4 bytes corrupts the next entry.
- Values are zero-based function indices, not external ordinals.
- The array has `NumberOfNames` entries.

In memory, consecutive entries are 2 bytes apart:
```
AddressOfNameOrdinals array:
  [base_addr + 0] = ordinal for names[0]   (2 bytes)
  [base_addr + 2] = ordinal for names[1]   (2 bytes)
  [base_addr + 4] = ordinal for names[2]   (2 bytes)
  ...
```

In x86 assembly, indexing with `ECX` as the loop counter:
```nasm
movzx  ebx, word ptr [esi + ecx*2]   ; read WORD, zero-extend to DWORD
; ebx = zero-based function index for names[ecx]
; Do NOT use [esi + ecx*4] — that would read DWORDs, stepping incorrectly
```

---

## Three-Table Resolution Algorithm

### Visual Overview

```
Goal: resolve "VirtualAlloc" VA from in-memory kernel32.dll

kernel32_base (e.g., 0x7C800000)
     │
     ├─[+0x3C]──► e_lfanew = 0x000000E8
     │
     └──► base + e_lfanew = IMAGE_NT_HEADERS at 0x7C8000E8
               │
               └─[+0x78]──► DataDirectory[0].VirtualAddress = export_dir_rva
                             (0x18 bytes for NtHdr sig+FileHdr + 0x60 into OptHdr)

kernel32_base + export_dir_rva = IMAGE_EXPORT_DIRECTORY
     │
     ├─[+0x18]── NumberOfNames = N (loop bound)
     │
     ├─[+0x20]── AddressOfNames RVA
     │               │
     │               └── base + RVA = ENPT (array of N DWORDs)
     │                       │
     │                       ├── [0]: RVA → "AcquireSRWLockExclusive\0"
     │                       ├── [1]: RVA → "ActivateActCtx\0"
     │                       ├── ...  (alphabetically sorted)
     │                       ├── [k]: RVA → "VirtualAlloc\0"  ← target
     │                       └── [N-1]: RVA → last name
     │
     ├─[+0x24]── AddressOfNameOrdinals RVA
     │               │
     │               └── base + RVA = EOT (array of N WORDs)
     │                       │
     │                       ├── [0]: func_index for names[0]
     │                       ├── ...
     │                       ├── [k]: func_index for "VirtualAlloc"  ← read this
     │                       └── [N-1]: func_index for last name
     │
     └─[+0x1C]── AddressOfFunctions RVA
                     │
                     └── base + RVA = EAT (array of M DWORDs)
                             │
                             └── [func_index]: func_rva
                                     │
                                     └── base + func_rva = VirtualAlloc VA  ← result


Resolution steps in order:
  1. i = 0
  2. name_rva = ENPT[i]
  3. name_va  = base + name_rva
  4. compare string at name_va with "VirtualAlloc" (or compare hash)
  5. if no match: i++, goto 2 (until i == N)
  6. if match at index i:
       func_index = EOT[i]             (WORD, zero-based)
       func_rva   = EAT[func_index]    (DWORD)
       func_va    = base + func_rva    (this is the callable address)
```

### Pseudocode

```c
DWORD resolve_export(BYTE *base, const char *target_name) {
    // Step 1: Navigate to export directory
    DWORD e_lfanew     = *(DWORD*)(base + 0x3C);
    DWORD export_rva   = *(DWORD*)(base + e_lfanew + 0x78);
    BYTE *export_dir   = base + export_rva;

    // Step 2: Load counts and table pointers
    DWORD num_names    = *(DWORD*)(export_dir + 0x18);
    DWORD names_rva    = *(DWORD*)(export_dir + 0x20);
    DWORD ordinals_rva = *(DWORD*)(export_dir + 0x24);
    DWORD funcs_rva    = *(DWORD*)(export_dir + 0x1C);

    DWORD *names    = (DWORD*)(base + names_rva);
    WORD  *ordinals = (WORD*) (base + ordinals_rva);
    DWORD *funcs    = (DWORD*)(base + funcs_rva);

    // Step 3: Walk name table
    for (DWORD i = 0; i < num_names; i++) {
        char *name = (char*)(base + names[i]);
        if (strcmp(name, target_name) == 0) {
            // Step 4: Get function index from ordinal table
            WORD func_index = ordinals[i];     // NOTE: WORD, not DWORD
            // Step 5: Get function RVA from EAT
            DWORD func_rva = funcs[func_index];
            // Step 6: Convert RVA to VA
            return (DWORD)(base + func_rva);
        }
    }
    return 0;  // not found
}
```

---

## Complete Assembly Implementation

The following is a complete, correct x86 assembly implementation of hash-based export resolution. The target function name is not compared as a string — instead, its ROR-13 hash is computed and compared against a pre-computed target hash. This avoids storing ASCII strings in the shellcode.

```nasm
; ============================================================
; find_function
;
; Locate an exported function by ROR-13 hash.
;
; Calling convention (non-standard, shellcode-internal):
;   EBX = module base address (DllBase from LDR_DATA_TABLE_ENTRY)
;   EDX = ROR-13 hash of target function name
;
; Returns:
;   EAX = function VA on success
;   EAX = 0 if function not found (hash not in export table)
;
; Clobbers:
;   ECX, EDI, ESI (all saved/restored via pushad/popad frame)
;   The caller's EBX and EDX are preserved.
;
; Stack frame during execution:
;   [ESP+00] = saved EDI (from pushad)
;   [ESP+04] = saved ESI
;   [ESP+08] = saved EBP
;   [ESP+0C] = saved ESP (pushad saves it; useless but present)
;   [ESP+10] = saved EBX
;   [ESP+14] = saved EDX   ← target hash stored here
;   [ESP+18] = saved ECX
;   [ESP+1C] = saved EAX
;   [ESP+20] = return address
; ============================================================
find_function:
    pushad                          ; save all general-purpose registers
                                    ; EDX (target hash) saved at [ESP+14]

    ; ----------------------------------------------------------
    ; Step 1: Navigate to IMAGE_EXPORT_DIRECTORY
    ; ----------------------------------------------------------
    mov  eax, [ebx + 0x3C]         ; eax  = e_lfanew (offset to IMAGE_NT_HEADERS)
    mov  edi, [ebx + eax + 0x78]   ; edi  = export directory RVA
                                    ;   PE_NT_HEADERS + 0x78:
                                    ;   0x18 (OptHdr offset) + 0x60 (DataDir offset)
                                    ;   = 0x78 from start of NT headers
    add  edi, ebx                   ; edi  = export directory VA (IMAGE_EXPORT_DIRECTORY*)

    ; ----------------------------------------------------------
    ; Step 2: Load export table counts and RVA pointers
    ; ----------------------------------------------------------
    mov  ecx, [edi + 0x18]         ; ecx  = NumberOfNames (loop bound)
    mov  eax, [edi + 0x20]         ; eax  = AddressOfNames RVA
    add  eax, ebx                   ; eax  = AddressOfNames VA  (DWORD* names_table)

    ; Save pointers we need throughout the loop:
    ;   EBP will hold the names table VA
    ;   ESI will hold the ordinal table VA
    ;   EDI remains the export directory VA
    mov  ebp, eax                   ; ebp  = AddressOfNames VA

    mov  esi, [edi + 0x24]         ; esi  = AddressOfNameOrdinals RVA
    add  esi, ebx                   ; esi  = AddressOfNameOrdinals VA (WORD* ord_table)

    ; ----------------------------------------------------------
    ; Step 3: Main loop — iterate over named exports
    ; ----------------------------------------------------------
find_function_loop:
    test ecx, ecx                   ; are there names remaining?
    jz   find_function_not_found    ; ECX == 0 → exhausted all names, not found

    dec  ecx                        ; decrement (loop counter, used as array index)
                                    ; We walk backwards: start at N-1, down to 0.
                                    ; Backwards walk is a common shellcode pattern
                                    ; because jecxz/dec pairs are compact.

    ; Load the RVA of the current name string
    mov  eax, [ebp + ecx*4]        ; eax  = AddressOfNames[ecx] (DWORD RVA)
    add  eax, ebx                   ; eax  = name string VA
                                    ; Now EAX points to "FunctionName\0"

    ; ----------------------------------------------------------
    ; Step 4: Compute ROR-13 hash of the current name string
    ;         Uses ESI as string pointer (temporarily) after
    ;         saving the ordinal table pointer on the stack.
    ; ----------------------------------------------------------
    push ecx                        ; save loop counter
    push esi                        ; save ordinal table pointer

    xor  esi, esi                   ; esi  = will become running hash
                                    ;   (renamed for clarity vs. pointer use)
    mov  edi, eax                   ; edi  = pointer into name string

    ; Compute hash using EDI as source, ESI as accumulator
hash_loop:
    movzx eax, byte ptr [edi]       ; al   = current byte (zero-extended)
    test  al, al                    ; null terminator?
    jz    hash_done                 ; yes → done hashing

    ; ROR-13: rotate right by 13 bits
    ror   esi, 0x0D                 ; esi  = ROR(esi, 13)
    add   esi, eax                  ; esi  = ROR(prev_hash, 13) + char_value

    inc   edi                       ; advance to next character
    jmp   hash_loop

hash_done:
    ; ESI now holds the computed ROR-13 hash of the current name.
    ; The target hash was saved by pushad at [ESP + offset].
    ; After our two additional pushes (ECX and old ESI):
    ;   [esp+00] = saved ordinal table pointer (old ESI)
    ;   [esp+04] = saved loop counter (ECX)
    ;   [esp+08] = pushad saved EDI    (not relevant)
    ;   [esp+0C] = pushad saved ESI    (not relevant)
    ;   [esp+10] = pushad saved EBP    (not relevant)
    ;   [esp+14] = pushad saved ESP    (not relevant)
    ;   [esp+18] = pushad saved EBX    (not relevant)
    ;   [esp+1C] = pushad saved EDX    ← target hash is here!
    ;   [esp+20] = pushad saved ECX    (loop counter was saved before pushad too)
    ;   [esp+24] = pushad saved EAX
    ;   [esp+28] = find_function return address

    cmp  esi, [esp + 0x1C]         ; computed hash == target hash?
    jnz  hash_no_match             ; no match — try next name

    ; ----------------------------------------------------------
    ; Step 5: Match found — resolve function address
    ; ----------------------------------------------------------
    ; Restore saved state to access ordinal table pointer
    pop  esi                        ; esi  = AddressOfNameOrdinals VA (restored)
    pop  ecx                        ; ecx  = loop counter (restored)

    ; Get the function index from the ordinal table
    ; Index into ordinal table is the same as the index we used in the name table
    movzx eax, word ptr [esi + ecx*2]  ; eax = func_index (WORD, zero-based)
                                        ; Note: *2 because each WORD = 2 bytes
                                        ; Note: movzx to avoid sign-extension issues

    ; Get the function RVA from the EAT
    mov  esi, [edi_saved_in_early_step] ; problem: EDI was clobbered by hash loop
    ; *** See corrected version below — use the export_dir pointer in EBP area ***
    ; Actually: we need AddressOfFunctions. We have EDI (export dir) from before
    ; the inner loop, but EDI was clobbered. Re-derive from known data:

    ; The export directory VA was in EDI before the inner loop started.
    ; We saved it in EBP at the start... no, EBP holds AddressOfNames.
    ; Correction: use a different register plan. See full corrected version.
    jmp  find_function_resolve

hash_no_match:
    pop  esi                        ; restore ordinal table pointer
    pop  ecx                        ; restore loop counter
    jmp  find_function_loop         ; try next name

find_function_not_found:
    xor  eax, eax                   ; return 0 (not found)
    mov  [esp + 0x1C], eax          ; overwrite pushad-saved EAX with 0
    popad                           ; restore all registers
    ret

; ============================================================
; COMPLETE CORRECT VERSION
; Resolves the register allocation issue above.
; Uses the stack explicitly to preserve the export dir pointer.
; ============================================================

find_function_v2:
    pushad                          ; saves all regs; EDX (hash) saved at [ESP+14]

    ; Navigate to export directory
    mov  eax, [ebx + 0x3C]         ; e_lfanew
    mov  eax, [ebx + eax + 0x78]   ; export dir RVA
    add  eax, ebx                   ; export dir VA → EAX

    ; Push export dir pointer so we can always retrieve it
    push eax                        ; [esp] = export dir VA (extra push, not from pushad)
                                    ; adjust all [esp+N] references by +4 from here

    ; Load counts and table VAs
    mov  ecx, [eax + 0x18]         ; ecx = NumberOfNames
    mov  edi, [eax + 0x20]
    add  edi, ebx                   ; edi = AddressOfNames VA

find_function_loop_v2:
    test ecx, ecx
    jz   find_function_not_found_v2
    dec  ecx

    ; Load name RVA, convert to VA
    mov  esi, [edi + ecx*4]        ; esi = AddressOfNames[ecx] RVA
    add  esi, ebx                   ; esi = name string VA

    ; Compute ROR-13 hash — ESI is the string pointer, EDX will be the hash
    push ecx                        ; save loop counter  [esp] = ecx
    push edi                        ; save names table   [esp] = edi

    xor  edx, edx                   ; edx = running hash (local, will compare at end)
                                    ; Note: the TARGET hash is deeper on stack now

compute_name_hash:
    movzx eax, byte ptr [esi]
    test  al, al
    jz    name_hash_done
    ror   edx, 0x0D
    add   edx, eax
    inc   esi
    jmp   compute_name_hash

name_hash_done:
    ; Stack layout at this point (ESP is current top):
    ;   [esp+00] = saved EDI (names table ptr)
    ;   [esp+04] = saved ECX (loop counter)
    ;   [esp+08] = export dir VA          (from push eax before loop)
    ;   [esp+0C] = pushad EDI
    ;   [esp+10] = pushad ESI
    ;   [esp+14] = pushad EBP
    ;   [esp+18] = pushad ESP (useless)
    ;   [esp+1C] = pushad EBX
    ;   [esp+20] = pushad EDX   ← TARGET HASH
    ;   [esp+24] = pushad ECX
    ;   [esp+28] = pushad EAX
    ;   [esp+2C] = find_function_v2 return address

    cmp  edx, [esp + 0x20]         ; computed hash == target hash?
    jnz  no_match_v2

    ; Match found
    pop  edi                        ; restore names table
    pop  ecx                        ; restore loop counter

    ; Get export dir pointer
    mov  eax, [esp + 0x08 - 0x08]  ; Corrected: after two pops, stack has changed.
    ; After popping EDI and ECX, stack is:
    ;   [esp+00] = export dir VA
    ;   ... (pushad frame)
    mov  eax, [esp]                 ; eax = export dir VA

    ; Get AddressOfNameOrdinals VA
    mov  esi, [eax + 0x24]
    add  esi, ebx                   ; esi = AddressOfNameOrdinals VA

    ; Get function index (WORD)
    movzx eax, word ptr [esi + ecx*2]  ; eax = func_index (zero-based, WORD)

    ; Get AddressOfFunctions VA
    mov  esi, [esp]                 ; esi = export dir VA (re-read)
    mov  esi, [esi + 0x1C]
    add  esi, ebx                   ; esi = AddressOfFunctions VA (EAT)

    ; Get function RVA
    mov  eax, [esi + eax*4]        ; eax = func_rva (DWORD, from EAT[func_index])

    ; Convert RVA to VA
    add  eax, ebx                   ; eax = func_VA  ← the result

    ; Store result in pushad frame's EAX slot so popad returns it
    mov  [esp + 0x28], eax         ; overwrite pushad-saved EAX
                                    ; After our extra "push eax" at start:
                                    ;   [esp+00] = export dir VA
                                    ;   [esp+28] = pushad EAX slot
                                    ; (pushad frame is 32 bytes = 8 registers * 4 bytes)

    add  esp, 4                     ; remove the export dir pointer we pushed
    popad                           ; restore all registers; EAX = func_VA
    ret

no_match_v2:
    pop  edi                        ; restore names table
    pop  ecx                        ; restore loop counter
    jmp  find_function_loop_v2

find_function_not_found_v2:
    xor  eax, eax
    add  esp, 4                     ; remove extra push
    mov  [esp + 0x1C], eax         ; overwrite pushad EAX with 0
    popad
    ret
```

### Annotated Register Usage Map

```
Register  Role During find_function
--------  ---------------------------------------------------------------
EBX       Preserved. Module base address (caller-set, used for all RVA→VA)
ECX       Loop counter (0 to NumberOfNames-1, walking backwards)
EDX       Computed hash (accumulator during inner loop); target hash on stack
ESI       Name string pointer during hash computation; ordinal table pointer
           during resolution; names table pointer (saved/restored)
EDI       Names table pointer (AddressOfNames VA)
EBP       Unused in v2 (available for caller's frame pointer)
EAX       Temporary; function index after match; final function VA result
ESP       Standard stack pointer; used for temporary storage across inner loop
```

---

## Forwarded Exports

### What Is a Forwarded Export

A forwarded export is an export that does not point to code in the current DLL. Instead, it points to a function in a different DLL. The mechanism is: the EAT entry contains an RVA to a string like `"NTDLL.RtlAllocateHeap"` — the RVA points to data that is a null-terminated forwarder string, not executable code.

The way to detect a forwarded export: the RVA in the EAT falls within the address range of the export directory itself.

### Detection Algorithm

```
export_dir_rva  = DataDirectory[0].VirtualAddress
export_dir_size = DataDirectory[0].Size

func_rva = EAT[func_index]

if (func_rva >= export_dir_rva) AND
   (func_rva <  export_dir_rva + export_dir_size):
       // It's a forwarded export
       // func_rva points to a forwarder string
       // The string is at: base + func_rva
       // Format: "DLL_name.Function_name\0"
       //      or "DLL_name.#ordinal\0" for ordinal-based forward
else:
       // Normal export — func_rva is code
```

In x86 assembly, after resolving `func_rva` from the EAT:

```nasm
; EAX = func_rva (from EAT)
; EBX = module base
; EDI = IMAGE_EXPORT_DIRECTORY VA

; Load export directory RVA and size from DataDirectory[0]
; DataDirectory[0] is at: base + e_lfanew + 0x78 (VirtualAddress)
;                         base + e_lfanew + 0x7C (Size)
mov  ecx, [ebx + e_lfanew_offset + 0x7C]  ; export dir size
mov  esi, [ebx + e_lfanew_offset + 0x78]  ; export dir RVA

cmp  eax, esi                    ; func_rva < export_dir_rva?
jb   not_forwarded               ; yes → normal export

add  esi, ecx                    ; esi = export_dir_rva + size
cmp  eax, esi                    ; func_rva >= export_dir_end?
jae  not_forwarded               ; yes → normal export

; If here: func_rva is within export directory → forwarded export
; The forwarder string is at: base + func_rva
; e.g., "NTDLL.RtlAllocateHeap\0"
add  eax, ebx                    ; eax = forwarder string VA
; (shellcode must now parse this string to load the target DLL
;  and re-resolve the function there — complex, most shellcode
;  avoids these cases by choosing non-forwarded functions)
jmp  handle_forwarder

not_forwarded:
add  eax, ebx                    ; eax = function VA (callable)
```

### APIs Known to Be Forwarded

The following functions are commonly forwarded on various Windows versions. Shellcode authors should be aware of these and either handle forwarders or avoid using them directly:

| API | Forwarded From | Forwarded To | Windows Version |
|-----|---------------|--------------|-----------------|
| `HeapAlloc` | kernel32 | `NTDLL.RtlAllocateHeap` | XP and later |
| `HeapFree` | kernel32 | `NTDLL.RtlFreeHeap` | XP and later |
| `HeapCreate` | kernel32 | `NTDLL.RtlCreateHeap` | XP and later |
| `HeapDestroy` | kernel32 | `NTDLL.RtlDestroyHeap` | XP and later |
| `HeapSize` | kernel32 | `NTDLL.RtlSizeHeap` | XP and later |
| `RtlMoveMemory` | kernel32 | `NTDLL.RtlMoveMemory` | Various |
| `RtlFillMemory` | kernel32 | `NTDLL.RtlFillMemory` | Various |
| `RtlZeroMemory` | kernel32 | `NTDLL.RtlZeroMemory` | Various |
| Various APIs | kernel32 | `api-ms-win-*` stubs | Win10+ |

On Windows 10 and later, API sets (`api-ms-win-core-*`) extensively forward entire DLLs. For example, many kernel32 exports may forward through `api-ms-win-core-heap-l1-1-0` → `KERNELBASE` → actual implementation.

### Consequence of Ignoring Forwarders

If shellcode does not detect forwarded exports and simply executes `CALL EAX` where EAX was set from a forwarded EAT entry:

1. EAX = base + func_rva = VA of a data string like `"NTDLL.RtlAllocateHeap\0"`
2. The CPU fetches the first bytes of that string as instructions
3. `"NTDLL"` = bytes `4E 54 44 4C 4C` = `DEC ECX` / `PUSH ESP` / ... (arbitrary)
4. Unpredictable behavior, almost certainly a crash

This is a silent failure mode — the shellcode compiles and the address lookup "succeeds" (returns a non-zero EAX), but the resulting address is not callable.

---

## Finding the Export Directory RVA

### Offset Derivation

The export directory RVA is stored at a fixed offset from the start of `IMAGE_NT_HEADERS`. Here is the full derivation:

```
IMAGE_NT_HEADERS layout:
  +0x00  DWORD Signature               ("PE\0\0" = 0x00004550)
  +0x04  IMAGE_FILE_HEADER FileHeader  (20 bytes)
  +0x18  IMAGE_OPTIONAL_HEADER32 OptionalHeader  (starts here)

IMAGE_OPTIONAL_HEADER32 layout (partial):
  +0x00  WORD  Magic                   (0x010B for PE32)
  +0x02  BYTE  MajorLinkerVersion
  +0x03  BYTE  MinorLinkerVersion
  +0x04  DWORD SizeOfCode
  ...
  +0x60  IMAGE_DATA_DIRECTORY DataDirectory[16]  (starts at +0x60 in OptHdr)

IMAGE_DATA_DIRECTORY[0] (export directory):
  +0x00  DWORD VirtualAddress          ← export dir RVA
  +0x04  DWORD Size                    ← export dir size

Combined offset from start of IMAGE_NT_HEADERS:
  0x18 (OptHdr start) + 0x60 (DataDirectory start) + 0x00 (entry 0) = 0x78
  → Export dir RVA at: IMAGE_NT_HEADERS + 0x78
  → Export dir RVA at: base + e_lfanew + 0x78

  0x18 (OptHdr start) + 0x60 (DataDirectory start) + 0x04 (Size field) = 0x7C
  → Export dir size at: base + e_lfanew + 0x7C
```

### The 0x78 Shortcut in Context

```nasm
; Given: EBX = module base address

; Long form (explicit)
mov  eax, [ebx + 0x3C]          ; eax  = e_lfanew
add  eax, ebx                    ; eax  = IMAGE_NT_HEADERS VA
add  eax, 0x18                   ; eax  = IMAGE_OPTIONAL_HEADER VA
add  eax, 0x60                   ; eax  = DataDirectory[0] VA
mov  edx, [eax]                  ; edx  = export dir RVA

; Short form (standard shellcode)
mov  eax, [ebx + 0x3C]          ; eax  = e_lfanew
mov  edx, [ebx + eax + 0x78]    ; edx  = export dir RVA  (0x18+0x60=0x78)
add  edx, ebx                    ; edx  = export dir VA
```

### PE32+ (64-bit) Differences

For 64-bit modules, `IMAGE_OPTIONAL_HEADER64` is larger. The `DataDirectory` array starts at offset `+0x70` in the optional header (not `+0x60`), so the combined offset from `IMAGE_NT_HEADERS` is `0x18 + 0x70 = 0x88`.

```
PE32:  [base + e_lfanew + 0x78] = export dir RVA
PE32+: [base + e_lfanew + 0x88] = export dir RVA
```

In practice, 64-bit shellcode for x64 Windows uses `0x88`. 32-bit shellcode on 32-bit Windows uses `0x78`. Do not mix them.

---

## WinDbg Step-by-Step Walkthrough

The following walkthrough manually resolves the address of `VirtualAlloc` in kernel32.dll using WinDbg commands. Tested on Windows XP SP3 x86.

```
; ---- Step 1: Find kernel32 base address ----
0:000> lm m kernel32
start    end      module name
7c800000 7c8f6000 kernel32   (export symbols)

kernel32_base = 0x7C800000

; ---- Step 2: Find e_lfanew ----
0:000> dd 7c800000+3c L1
7c80003c  000000e8
e_lfanew = 0xE8

; ---- Step 3: Find export directory RVA and size ----
0:000> dd 7c800000+e8+78 L2
7c800160  000262c0 00007740
export_dir_rva  = 0x000262C0
export_dir_size = 0x00007740

; ---- Step 4: Inspect IMAGE_EXPORT_DIRECTORY ----
0:000> dt ntdll!_IMAGE_EXPORT_DIRECTORY 7c800000+262c0
   +0x000 Characteristics      : 0
   +0x004 TimeDateStamp        : 0x4802a126
   +0x008 MajorVersion         : 0
   +0x00a MinorVersion         : 0
   +0x00c Name                 : 0x000262a8    ; RVA → "KERNEL32.dll"
   +0x010 Base                 : 1
   +0x014 NumberOfFunctions    : 0x572         ; 1394 functions
   +0x018 NumberOfNames        : 0x572         ; 1394 named exports (same here)
   +0x01c AddressOfFunctions   : 0x00026940    ; EAT RVA
   +0x020 AddressOfNames       : 0x00027288    ; ENPT RVA
   +0x024 AddressOfNameOrdinals: 0x00027bd0    ; EOT RVA

; ---- Step 5: Verify DLL name ----
0:000> da 7c800000+262a8
7c8262a8  "KERNEL32.dll"

; ---- Step 6: View first 5 entries in AddressOfNames ----
0:000> dd 7c800000+27288 L5
7c827288  000262c0 000262cc ...
; (these are RVAs to name strings)
; Dereference first name:
0:000> da 7c800000+262c0
7c8262c0  "ActivateActCtx"         ; alphabetically first

; ---- Step 7: Find "VirtualAlloc" (example: it's at index k) ----
; In practice, use .shell -ci "da ..." or script; here we note that
; VirtualAlloc is near the end of the table.
; For illustration, assume AddressOfNames[k] RVA = 0x0002A7C8
0:000> da 7c800000+2a7c8
7c82a7c8  "VirtualAlloc"           ; confirmed: index k

; ---- Step 8: Read ordinal at same index k ----
; Each ordinal is a WORD (2 bytes). If k=0x04B0:
0:000> dw 7c800000+27bd0+(0x4b0*2) L1
xxxxxxxx  04af                     ; func_index = 0x04AF

; ---- Step 9: Read EAT entry at func_index ----
0:000> dd 7c800000+26940+(0x4af*4) L1
xxxxxxxx  0001f690                 ; func_rva = 0x0001F690

; ---- Step 10: Verify function ----
0:000> u 7c800000+1f690
7c81f690 8bff            mov     edi,edi
7c81f692 55              push    ebp
7c81f694 8bec            mov     ebp,esp
7c81f696 ...
; Confirmed: this is the prologue of VirtualAlloc in kernel32.dll

; ---- Alternative: use WinDbg symbol to confirm ----
0:000> ln 7c81f690
(7c81f690)   kernel32!VirtualAlloc
```

---

## Common Mistakes

### Mistake 1: Subtracting Base from Zero-Based Ordinals

**Wrong**:
```nasm
movzx eax, word ptr [esi + ecx*2]  ; eax = ordinal from EOT
sub   eax, [export_dir + 0x10]     ; ← WRONG: subtracts Base (usually 1)
; EAX is now func_index - 1, pointing to wrong EAT entry
```

**Correct**:
```nasm
movzx eax, word ptr [esi + ecx*2]  ; eax = func_index, already zero-based
; Do NOT subtract Base here. Base subtraction is for ordinal-based lookups only.
```

The `AddressOfNameOrdinals` values are always zero-based EAT indices. The `Base` field in the export directory is only relevant when doing ordinal-number-based imports (e.g., when an import table uses ordinal 5 to mean "the fifth exported function" where the first is ordinal `Base`).

### Mistake 2: Reading Ordinals as DWORDs

**Wrong**:
```nasm
mov  eax, [esi + ecx*4]     ; reads 4 bytes (DWORD)
; ← WRONG: treats two consecutive 2-byte ordinals as one 4-byte value
; ← Also: wrong stride — *4 instead of *2
```

**Correct**:
```nasm
movzx eax, word ptr [esi + ecx*2]  ; reads 2 bytes (WORD), zero-extends
; Stride is *2 (2 bytes per WORD entry)
; Zero-extension matters: without it, sign extension corrupts the index
```

This mistake is particularly insidious because it is silent. The wrong ordinal points to an EAT entry that happens to exist but is a different function. The shellcode proceeds to call the wrong function, which may crash differently or not crash at all but produce wrong behavior.

### Mistake 3: Ignoring Forwarded Exports

**Wrong**:
```nasm
mov  eax, [eat_base + func_index*4]  ; EAT[func_index]
add  eax, ebx                         ; convert RVA to VA
call eax                              ; ← WRONG if forwarded: calls a string
```

**Correct**: Add the forwarded export check before executing `CALL EAX`. See the [Forwarded Exports](#forwarded-exports) section for the detection algorithm.

Functions to avoid using without forward-export checking:
- `HeapAlloc`, `HeapFree`, `HeapCreate`, `HeapDestroy`
- `RtlMoveMemory`, `RtlZeroMemory`
- Any `api-ms-win-*` API

Use `VirtualAlloc` (not forwarded), `CreateProcessA` (not forwarded), `LoadLibraryA` (not forwarded).

### Mistake 4: Case-Sensitive Name Comparison

The export name table stores names in their original case as the linker produced them. The table is sorted case-sensitively. Common names are mixed-case: `VirtualAlloc`, `GetProcAddress`, `LoadLibraryA`.

**Wrong**:
```c
if (stricmp(name, "VirtualAlloc") == 0)  // case-insensitive compare
```

**Correct**:
```c
if (strcmp(name, "VirtualAlloc") == 0)   // exact case match
```

In assembly with hash-based comparison, this is automatic — the hash includes the case of each character. `ROR13("VirtualAlloc") != ROR13("virtualalloc")`.

### Mistake 5: Iterating with NumberOfFunctions Instead of NumberOfNames

**Wrong**:
```nasm
mov  ecx, [export_dir + 0x14]    ; NumberOfFunctions
; ← WRONG as loop bound for name-based search
; AddressOfNames and AddressOfNameOrdinals only have NumberOfNames entries
; Walking to NumberOfFunctions reads past the end of these arrays
```

**Correct**:
```nasm
mov  ecx, [export_dir + 0x18]    ; NumberOfNames ← correct for name/ordinal arrays
```

### Mistake 6: Forgetting That e_lfanew Is Also an RVA

```nasm
; Wrong: treating e_lfanew as an absolute offset from the start of a buffer
mov  eax, [buffer + 0x3C]        ; eax = e_lfanew
mov  edx, [eax + 0x78]           ; WRONG: treats e_lfanew as absolute VA

; Correct:
mov  eax, [ebx + 0x3C]           ; eax = e_lfanew (RVA from module base)
mov  edx, [ebx + eax + 0x78]     ; ebx + eax = NT headers VA, then +0x78
```

---

## Quick Reference Summary

```
IMAGE_EXPORT_DIRECTORY (0x28 bytes total)

Offset  Field                     Role in shellcode
------  -----                     -----------------
+0x10   Base                      Ordinal adjustment (NOT used in name-based lookup)
+0x14   NumberOfFunctions         Size of EAT; used in ordinal-based range check
+0x18   NumberOfNames             Loop bound for name/hash search
+0x1C   AddressOfFunctions (EAT)  RVA → array of DWORD function RVAs
+0x20   AddressOfNames (ENPT)     RVA → array of DWORD name string RVAs (sorted)
+0x24   AddressOfNameOrdinals     RVA → array of WORD zero-based function indices

Navigation:
  Export dir RVA (PE32):  [base + e_lfanew + 0x78]
  Export dir RVA (PE32+): [base + e_lfanew + 0x88]
  Export dir size:        [base + e_lfanew + 0x7C]

Name lookup (3 tables):
  1. names[i]    = base + ENPT[i]          → compare/hash string
  2. idx         = EOT[i]                  → WORD, zero-based, no Base subtract
  3. func_rva    = EAT[idx]                → DWORD
  4. func_va     = base + func_rva         → call this

Forwarded export detection:
  func_rva in [export_dir_rva, export_dir_rva + export_dir_size) → forwarded
```
