# Export Table Parsing

## Purpose

Given the base address of a loaded PE module (obtained via PEB walking), export table parsing extracts the address of a specific exported function. This is the second major component of shellcode API resolution: once we have a module base, we parse its export directory to find individual function addresses by comparing hashed or literal names.

## Exploit Relevance

Shellcode cannot use the Windows loader's import resolution machinery. After locating kernel32.dll via PEB walking, the shellcode must independently replicate what `GetProcAddress` does internally — navigate the PE export directory structures and resolve names to virtual addresses. This technique is also used to re-implement `LoadLibraryA` lookup, socket functions, and any API the shellcode needs.

Understanding the export table is also critical for:
- Bypassing EDR/AV hooks by resolving directly from ntdll (syscall stubs)
- Following forwarder exports (e.g., kernel32 forwarding to kernelbase)
- Writing custom GetProcAddress implementations
- Enumerating a module's full export list during post-exploitation

---

## PE Structure Overview

### The PE Header Chain

Every PE image (DLL or EXE) begins with an MZ header, followed by a PE header pointed to by `e_lfanew`:

```
module_base + 0x00    = IMAGE_DOS_HEADER.e_magic    ("MZ" = 0x5A4D)
module_base + 0x3c    = IMAGE_DOS_HEADER.e_lfanew   (RVA to IMAGE_NT_HEADERS)

module_base + e_lfanew = IMAGE_NT_HEADERS:
  +0x00  Signature        ("PE\0\0" = 0x00004550)
  +0x04  FileHeader       (IMAGE_FILE_HEADER, 20 bytes)
  +0x18  OptionalHeader   (IMAGE_OPTIONAL_HEADER32, 224 bytes for PE32)
```

### IMAGE_OPTIONAL_HEADER32 Layout (Relevant Fields)

```
OptionalHeader (at NT_HEADERS + 0x18):
  +0x00  Magic              (0x010B for PE32, 0x020B for PE32+/x64)
  +0x10  AddressOfEntryPoint
  +0x1c  ImageBase
  +0x38  SizeOfImage
  +0x3c  CheckSum
  +0x5c  NumberOfRvaAndSizes
  +0x60  DataDirectory[0]   = Export Directory (IMAGE_DATA_DIRECTORY)
  +0x68  DataDirectory[1]   = Import Directory
  ...
```

The Export Directory DataDirectory entry is at `OptionalHeader + 0x60`:
```
IMAGE_DATA_DIRECTORY:
  +0x00  VirtualAddress (DWORD) = RVA of IMAGE_EXPORT_DIRECTORY
  +0x04  Size           (DWORD) = byte size of the export directory
```

### Offset Summary (from module_base)

```
module_base + 0x3c                         = e_lfanew
module_base + e_lfanew + 0x18 + 0x60      = ExportDir.VirtualAddress
module_base + e_lfanew + 0x18 + 0x64      = ExportDir.Size
```

Or equivalently:
```
nt_headers  = module_base + [module_base + 0x3c]
opt_header  = nt_headers + 0x18
export_rva  = [opt_header + 0x60]
export_size = [opt_header + 0x64]
export_dir  = module_base + export_rva
```

---

## IMAGE_EXPORT_DIRECTORY Structure

```c
typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD  Characteristics;       // +0x00  reserved, always 0
    DWORD  TimeDateStamp;         // +0x04  module build timestamp
    WORD   MajorVersion;          // +0x08
    WORD   MinorVersion;          // +0x0a
    DWORD  Name;                  // +0x0c  RVA to module name string
    DWORD  Base;                  // +0x10  ordinal base (subtract to get EAT index)
    DWORD  NumberOfFunctions;     // +0x14  total entries in AddressOfFunctions
    DWORD  NumberOfNames;         // +0x18  entries in AddressOfNames / AddressOfNameOrdinals
    DWORD  AddressOfFunctions;    // +0x1c  RVA to EAT (array of function RVAs)
    DWORD  AddressOfNames;        // +0x20  RVA to array of RVAs to name strings
    DWORD  AddressOfNameOrdinals; // +0x24  RVA to array of WORDs (ordinals)
} IMAGE_EXPORT_DIRECTORY;
```

### The Three Export Tables

**AddressOfNames (ENT — Export Name Table):**
An array of `NumberOfNames` DWORDs, each being an RVA to a null-terminated ASCII string (the function name). The array is sorted alphabetically, enabling binary search, though shellcode typically uses a linear scan with hashing.

**AddressOfNameOrdinals (EOT — Export Ordinal Table):**
An array of `NumberOfNames` WORDs. `AddressOfNameOrdinals[i]` is the index into `AddressOfFunctions` for the function named by `AddressOfNames[i]`. This index is **0-based relative to the EAT** — it is not the "external ordinal" (which would require adding `Base`).

**AddressOfFunctions (EAT — Export Address Table):**
An array of `NumberOfFunctions` DWORDs, each being an RVA to a function. Indexed by the 0-based ordinal from the EOT.

### The Three-Table Lookup Process

```
Given: target function name (or hash)

for i in range(NumberOfNames):
    name_rva  = AddressOfNames[i]
    name_str  = module_base + name_rva        ; null-terminated ASCII
    name_hash = hash(name_str)

    if name_hash == target_hash:
        ordinal   = AddressOfNameOrdinals[i]  ; 0-based EAT index (WORD)
        func_rva  = AddressOfFunctions[ordinal]
        func_va   = module_base + func_rva
        return func_va
```

### Critical Ordinal Math

The ordinal read from `AddressOfNameOrdinals[i]` is directly used as a zero-based index into `AddressOfFunctions`. Do not subtract the `Base` field:

```
func_rva = AddressOfFunctions[ AddressOfNameOrdinals[i] ]   ; CORRECT

; NOT:
; biased_ordinal = external_ordinal - Base
; func_rva = AddressOfFunctions[biased_ordinal]   ; only when looking up by external ordinal
```

The `Base` field is only relevant when the caller is resolving by external ordinal number (e.g., `GetProcAddress(hModule, MAKEINTRESOURCE(17))`), not when resolving through the name tables.

---

## Full ASCII Diagram

```
module_base
    |
    +-> [+0x3c] = e_lfanew
              |
              v
         IMAGE_NT_HEADERS (module_base + e_lfanew)
              |
              +-> OptionalHeader (+0x18 from NT headers)
                       |
                       +-> DataDirectory[0] (+0x60 from OptionalHeader)
                                  |
                                  +-> VirtualAddress = export_dir_rva
                                  +-> Size = export_dir_size
                                            |
                                            v
                              IMAGE_EXPORT_DIRECTORY (module_base + export_dir_rva)
                                  |
                                  +-> NumberOfNames        (how many named exports)
                                  +-> AddressOfNames       (RVA to ENT)
                                  +-> AddressOfNameOrdinals (RVA to EOT)
                                  +-> AddressOfFunctions   (RVA to EAT)
                                                |
         ENT: [rva0, rva1, rva2, ...]           |
              |                                 |
              v                                 v
         name strings: "AddAtomA\0", "AddAtomW\0", ...
                                                |
         EOT: [ord0, ord1, ord2, ...]  <--------+
              (WORD values, 0-based EAT index)
                   |
                   v
         EAT: [func_rva0, func_rva1, ...] (indexed by ordinal from EOT)
              |
              v
         function_va = module_base + EAT[EOT[name_index]]
```

---

## Full Assembly Implementation

The following implements a complete find_function routine accepting a module base and a hash value, returning the function's virtual address.

```asm
; ============================================================
; find_function
;
; Locates an exported function by ROR-13 hash.
;
; Input:  EBX = module base address (e.g., kernel32.dll)
;         ECX = target function name hash (ROR-13, see Hash_Algorithms.md)
; Output: EAX = function virtual address, 0 if not found
;
; Clobbers: EAX, EDX, ESI, EDI and registers via pushad/popad frame
; ============================================================

find_function:
    pushad                          ; save all general-purpose registers

    ; --------------------------------------------------------
    ; Step 1: Navigate to IMAGE_NT_HEADERS
    ; module_base + 0x3c = e_lfanew
    ; --------------------------------------------------------
    mov     eax, [ebx + 0x3c]       ; EAX = e_lfanew (offset to NT headers)
    add     eax, ebx                ; EAX = absolute address of IMAGE_NT_HEADERS

    ; --------------------------------------------------------
    ; Step 2: Get Export Directory RVA from DataDirectory[0]
    ; OptionalHeader starts at NT_HEADERS + 0x18
    ; DataDirectory[0].VirtualAddress at OptionalHeader + 0x60
    ; So: NT_HEADERS + 0x18 + 0x60 = NT_HEADERS + 0x78
    ; --------------------------------------------------------
    mov     eax, [eax + 0x78]       ; EAX = export directory RVA
                                    ; (0x18 opt header offset + 0x60 DataDir[0].VA
                                    ;  = 0x78 from NT headers base)
    add     eax, ebx                ; EAX = absolute export directory address

    ; --------------------------------------------------------
    ; Step 3: Extract the three export table pointers
    ; Store in convenient registers/stack
    ; --------------------------------------------------------
    mov     [esp - 0x04], eax       ; save export_dir address (use as ref)

    ; NumberOfNames at export_dir + 0x18
    mov     ecx, [eax + 0x18]       ; ECX = NumberOfNames (loop counter)

    ; AddressOfNames (ENT) at export_dir + 0x20
    mov     esi, [eax + 0x20]       ; ESI = RVA of ENT
    add     esi, ebx                ; ESI = absolute address of ENT (array of RVAs)

    ; --------------------------------------------------------
    ; Step 4: Loop over all named exports
    ; --------------------------------------------------------
.find_func_loop:
    jecxz   .find_func_not_found    ; if ECX == 0, exhausted all names

    dec     ecx                     ; decrement counter (we use ECX as 0-based index
                                    ; from the end to front, so current index = ECX)
                                    ; Note: some implementations count up; this
                                    ; counts down. Adjust ordinal lookup accordingly.

    ; --------------------------------------------------------
    ; Step 5: Get the current function name
    ; ENT[ECX] = RVA to name string
    ; --------------------------------------------------------
    mov     esi, [esp - 0x04]       ; reload export_dir
    mov     edi, [esi + 0x20]       ; EDI = RVA of ENT
    add     edi, ebx                ; EDI = absolute ENT
    mov     esi, [edi + ecx * 4]    ; ESI = RVA of current name string (ENT[ECX])
    add     esi, ebx                ; ESI = absolute address of name string

    ; --------------------------------------------------------
    ; Step 6: Compute ROR-13 hash of the name string
    ; (see Hash_Algorithms.md for detailed explanation)
    ; --------------------------------------------------------
    xor     edi, edi                ; EDI = running hash accumulator
    xor     eax, eax                ; EAX = current character

.hash_loop:
    lodsb                           ; AL = [ESI], ESI++  (load next char)
    test    al, al                  ; test for null terminator
    jz      .hash_done              ; if null, done hashing

    ror     edi, 0x0d               ; ROR-13 rotation of hash
    add     edi, eax                ; add current character value
    jmp     .hash_loop

.hash_done:
    ; --------------------------------------------------------
    ; Step 7: Compare computed hash to target hash (saved in
    ; original ECX via pushad — recover from stack frame)
    ; When using pushad, ECX is at [esp + 0x24 - 0x10] = [esp + 0x14]
    ; pushad layout (from top of stack after pushad):
    ;   [esp+0x00] = EDI
    ;   [esp+0x04] = ESI
    ;   [esp+0x08] = EBP
    ;   [esp+0x0c] = ESP (original)
    ;   [esp+0x10] = EBX
    ;   [esp+0x14] = EDX
    ;   [esp+0x18] = ECX  <-- target hash was in ECX before pushad
    ;   [esp+0x1c] = EAX
    ; --------------------------------------------------------
    cmp     edi, [esp + 0x18]       ; compare hash vs target (saved ECX)
    jnz     .find_func_loop         ; no match, try next

    ; --------------------------------------------------------
    ; Step 8: Hash matched — resolve the function address
    ; Reload ECX (current index into name tables)
    ; --------------------------------------------------------
    ; Reload export_dir
    mov     esi, [esp - 0x04]       ; ESI = export_dir

    ; Get ordinal from AddressOfNameOrdinals (EOT)
    ; EOT at export_dir + 0x24
    mov     edi, [esi + 0x24]       ; EDI = RVA of EOT
    add     edi, ebx                ; EDI = absolute EOT
    movzx   eax, word [edi + ecx * 2] ; EAX = ordinal at EOT[ECX] (WORD * 2)

    ; Get function RVA from AddressOfFunctions (EAT)
    ; EAT at export_dir + 0x1c
    mov     edi, [esi + 0x1c]       ; EDI = RVA of EAT
    add     edi, ebx                ; EDI = absolute EAT
    mov     eax, [edi + eax * 4]    ; EAX = function RVA at EAT[ordinal] (DWORD * 4)

    ; --------------------------------------------------------
    ; Step 9: Convert RVA to absolute VA
    ; --------------------------------------------------------
    add     eax, ebx                ; EAX = function_va = module_base + func_rva

    ; --------------------------------------------------------
    ; Step 10: Store result and return
    ; Write function VA into the EAX slot of the pushad frame
    ; so popad restores it into EAX.
    ; EAX slot in pushad frame is at [esp + 0x1c]
    ; --------------------------------------------------------
    mov     [esp + 0x1c], eax       ; patch pushad frame EAX slot

    popad                           ; restore all registers (EAX = function VA)
    ret

.find_func_not_found:
    popad                           ; restore registers
    xor     eax, eax                ; return 0 (not found)
    ret
```

### Corrected Version with Proper Count-Up Loop

The count-down loop above requires care with the ECX-as-index relationship. Here is a cleaner count-up version:

```asm
; ============================================================
; find_function_v2 — count-up loop, cleaner index handling
;
; Input:  EBX = module base address
;         EDX = target function name hash (ROR-13)
; Output: EAX = function virtual address, 0 if not found
; ============================================================

find_function_v2:
    pushad

    ; Navigate to NT Headers
    mov     eax, [ebx + 0x3c]       ; e_lfanew
    add     eax, ebx                ; EAX = NT Headers VA

    ; Get export directory VA
    mov     eax, [eax + 0x78]       ; export_dir RVA (NT+0x78)
    add     eax, ebx                ; EAX = export_dir VA
    push    eax                     ; [esp+0x20] = export_dir (after pushad used 0x20 bytes)
                                    ; Actually: pushad pushed 8 regs * 4 = 0x20 bytes
                                    ; then we push eax = another 4 bytes
                                    ; EDX (target hash) is at [esp + 0x20 + 0x14] = [esp + 0x34]

    ; Initialize loop counter
    mov     ecx, [eax + 0x18]       ; ECX = NumberOfNames
    xor     edi, edi                ; EDI = loop index (0)

.ff2_loop:
    cmp     edi, ecx                ; index >= NumberOfNames?
    jge     .ff2_not_found

    ; Get name RVA from ENT
    mov     esi, [esp]              ; reload export_dir from stack
    mov     eax, [esi + 0x20]       ; RVA of ENT
    add     eax, ebx                ; absolute ENT
    mov     esi, [eax + edi * 4]    ; ENT[i] = RVA of name string
    add     esi, ebx                ; ESI = absolute name string

    ; Hash the name (ROR-13)
    xor     eax, eax
    cdq                             ; EDX = 0 (also clears EDX for hash)
                                    ; Note: this clobbers EDX!
                                    ; Save target hash before this.
                                    ; Better: use a different register for hash accum.
    ; Use EBP-relative storage or stack for target hash in practice.
    ; This version stores accum in EAX:
    xor     eax, eax                ; hash = 0

.ff2_hash:
    movzx   ebp, byte [esi]         ; load byte (avoids clobbering SI advance)
    test    ebp, ebp
    jz      .ff2_hash_done
    ror     eax, 0x0d               ; ROR hash
    add     eax, ebp                ; add char
    inc     esi                     ; advance pointer
    jmp     .ff2_hash

.ff2_hash_done:
    ; Compare with target hash
    ; Target hash was in EDX (second input), saved in pushad frame at [esp+0x34]
    cmp     eax, [esp + 0x34]       ; [esp+0x20 pushad + 0x04 push eax + 0x10 edx offset]
    jne     .ff2_next

    ; Found — resolve address
    mov     esi, [esp]              ; export_dir
    mov     eax, [esi + 0x24]       ; RVA of EOT (AddressOfNameOrdinals)
    add     eax, ebx
    movzx   eax, word [eax + edi * 2] ; ordinal = EOT[i] (WORD)

    mov     esi, [esp]
    mov     esi, [esi + 0x1c]       ; RVA of EAT
    add     esi, ebx
    mov     eax, [esi + eax * 4]    ; func_rva = EAT[ordinal]
    add     eax, ebx                ; func_va

    ; Return via pushad frame
    add     esp, 4                  ; pop the extra push
    mov     [esp + 0x1c], eax       ; patch EAX slot in pushad frame
    popad
    ret

.ff2_next:
    inc     edi                     ; advance loop index
    jmp     .ff2_loop

.ff2_not_found:
    add     esp, 4
    popad
    xor     eax, eax
    ret
```

---

## Exact Offset Reference

### Getting from module_base to export directory (step by step)

```
[1] module_base + 0x3c   = e_lfanew (DWORD)
[2] module_base + [1]    = IMAGE_NT_HEADERS address
[3] [2] + 0x18           = IMAGE_OPTIONAL_HEADER32 address
[4] [3] + 0x60           = DataDirectory[0] (export dir entry)
        = [2] + 0x78     (shortcut: NT_HEADERS + 0x78)
[5] [4] + 0x00 = export directory RVA  (DWORD)
[6] module_base + [5]    = IMAGE_EXPORT_DIRECTORY address
```

**Common mistake**: using 0x70 instead of 0x60 for DataDirectory[0] offset within OptionalHeader. The correct value is 0x60. The value 0x70 is sometimes cited but reflects a confusion with the x64 OptionalHeader layout where DataDirectory[0] is at a different offset.

For x64 (PE32+):
```
OptionalHeader.Magic = 0x020B
OptionalHeader size  = 240 bytes (vs 224 for PE32)
DataDirectory[0].VirtualAddress = OptionalHeader + 0x70 (x64)
                                = NT_HEADERS + 0x18 + 0x70 = NT_HEADERS + 0x88
```

---

## Forwarded Export Handling

### What Is a Forwarded Export?

A forwarded export is a function where the `AddressOfFunctions[ordinal]` RVA points within the export directory itself (not outside it) and is a string of the form `"ModuleName.FunctionName"`. This is the PE loader's way of redirecting a function call to a different DLL.

**Detection**: after computing `func_va = module_base + func_rva`, check if `func_rva` falls within the export directory range:

```
if (func_rva >= export_dir_rva) AND
   (func_rva < export_dir_rva + export_dir_size):
    ; func_va is a forwarder string, not a function address
```

**Example**: On Windows 8+, many kernel32 functions forward to KernelBase.dll. If shellcode resolves `VirtualAlloc` from kernel32 on such a system, it may get a forwarder string like `"KERNELBASE.VirtualAlloc"`.

### Following a Forwarder

The forwarder string format is ASCII: `"DllName.FunctionName"` (dot-separated, null-terminated). The DLL name does not include the `.DLL` extension.

To follow the forwarder:
1. Read the ASCII string from `func_va`.
2. Parse out the DLL name (before the dot) and function name (after the dot).
3. Find the target DLL's base address (via PEB walk or LoadLibraryA).
4. Recursively call find_function on the target DLL with the function name.

```asm
; Pseudo-logic for forwarder detection and following
; (simplified — full implementation would require string parsing)

    ; After computing func_rva and func_va:
    ; EAX = func_rva, EBX = module_base
    mov     esi, [esp]              ; export_dir VA
    mov     ecx, [esp + 4]          ; export_dir_size

    ; export_dir_rva = export_dir - module_base
    mov     edx, esi
    sub     edx, ebx                ; EDX = export_dir_rva

    cmp     eax, edx                ; func_rva >= export_dir_rva?
    jl      .not_forwarder

    mov     ecx, [esi + 0x10]       ; ecx = NumberOfFunctions (reuse)
    ; Better: reload size from DataDirectory entry
    ; For simplicity, compare against a known bound:
    ; if func_rva < export_dir_rva + export_dir_size => forwarder
    ; This check is left as an exercise; the key insight is shown above.

.not_forwarder:
    ; func_va is a real function address
```

### Why Forwarders Matter for Shellcode

If shellcode calls a function that is actually a forwarder without following the chain, it executes the forwarder string as code — which will immediately crash (SIGSEGV / access violation). On Windows 8+ and Windows 10, a significant portion of kernel32 exports are forwarders to KernelBase.dll. Shellcode targeting only Windows 7 and earlier can often ignore forwarders; shellcode targeting Windows 8+ must handle them.

---

## Null Terminator and Bounds Safety

### Array Bounds Check

Always validate that the loop index does not exceed `NumberOfNames`:
```asm
    ; Before accessing ENT[i], EOT[i]:
    cmp     edi, ecx    ; edi = index, ecx = NumberOfNames
    jge     .not_found  ; index out of bounds
```

### Name String Null Terminator

ASCII function names in the ENT are null-terminated. The hash loop should terminate on reading 0x00:
```asm
.hash_loop:
    movzx   eax, byte [esi]
    test    eax, eax    ; null terminator?
    jz      .hash_done
    ror     edx, 0x0d   ; hash rotation
    add     edx, eax    ; accumulate
    inc     esi
    jmp     .hash_loop
```

Never use string functions (lodsb without null check, etc.) that assume a maximum length without validating against a bound.

---

## WinDbg Verification Workflows

### Dump the Export Directory

```windbg
; Get kernel32 base
lm m kernel32
; Assume base = 0x75f10000

; Read e_lfanew
dd 0x75f10000 + 0x3c L1
; e.g. output: 000000f0

; Read DataDirectory[0] from NT_HEADERS + 0x78
dd 0x75f10000 + 0xf0 + 0x78 L2
; First DWORD = export dir RVA
; Second DWORD = export dir size

; Dump IMAGE_EXPORT_DIRECTORY
r $t0 = 0x75f10000 + <export_rva>
dt ntdll!_IMAGE_EXPORT_DIRECTORY @$t0
```

### Dump Export Function Names

```windbg
; With export_dir at $t0 and module_base $t1:
r $t1 = 0x75f10000

; AddressOfNames RVA at export_dir + 0x20
r $t2 = poi(@$t0 + 0x20) + @$t1   ; absolute ENT

; Print first 5 function names
r $t3 = 0
.for (; @$t3 < 5; r $t3 = @$t3 + 1) {
    da @$t1 + poi(@$t2 + (@$t3 * 4))
}
```

### Verify a Specific Function Address

```windbg
; Resolve VirtualAlloc manually through export tables
; 1. Get export dir (as above)
; 2. Find "VirtualAlloc" in ENT (use s command to search)
s -a 0x75f10000 L?0x100000 "VirtualAlloc"

; 3. Note the index in ENT
; 4. Read corresponding ordinal from EOT
; 5. Read function RVA from EAT
; 6. Add module_base
; Compare against:
u kernel32!VirtualAlloc
```

### Check for Forwarders

```windbg
; Dump first 20 entries of EAT
r $t0 = <export_dir_va>
r $t1 = <module_base>
r $t2 = poi(@$t0 + 0x1c) + @$t1   ; absolute EAT
dd @$t2 L20

; For each RVA, check if it falls within export dir:
; export_dir_rva <= rva < export_dir_rva + export_dir_size => forwarder
; Use:
da @$t1 + <suspicious_rva>         ; dump as ASCII to see forwarder string
```

---

## x86 vs x64 Differences

| Field | PE32 (x86) | PE32+ (x64) |
|---|---|---|
| OptionalHeader.Magic | 0x010B | 0x020B |
| OptionalHeader size | 224 bytes | 240 bytes |
| DataDirectory[0] offset from NT headers | +0x78 | +0x88 |
| Pointer sizes in PE structures | 4 bytes (DWORDs) | 8 bytes (QWORDs) |
| EAT/ENT/EOT arrays | Same DWORD/WORD layout | Same (export tables unchanged) |
| IMAGE_EXPORT_DIRECTORY | Same structure on x64 | Identical layout |

The export directory structure itself (`IMAGE_EXPORT_DIRECTORY`) is identical for x86 and x64 — it uses DWORDs for all entries. Only the path to reach it via the Optional Header changes. This means the find_function inner loop (parsing ENT/EOT/EAT) is identical for both architectures; only the navigation to the export directory differs.

```asm
; x64 — navigate to export directory
; (replaces the first few instructions of find_function)
; RBX = module base

    mov     eax, [rbx + 0x3c]       ; e_lfanew (still a DWORD even on x64)
    add     rax, rbx                ; RAX = NT headers VA

    ; DataDirectory[0] at NT_HEADERS + 0x18 (opt header) + 0x70 (dir[0]) = +0x88
    mov     eax, [rax + 0x88]       ; export dir RVA
    add     rax, rbx                ; RAX = export dir VA
    ; ... rest of export parsing identical to x86 ...
```

---

## Common Mistakes

### Mistake 1: Wrong DataDirectory Offset (0x70 vs 0x60)

The DataDirectory[0] (export directory) is at:
- `OptionalHeader + 0x60` for PE32 (x86)
- `OptionalHeader + 0x70` for PE32+ (x64)

From the start of IMAGE_NT_HEADERS:
- x86: `NT_HEADERS + 0x78`
- x64: `NT_HEADERS + 0x88`

Using 0x70 in x86 code (a frequent error) reads the wrong DataDirectory entry (DataDirectory[2] = resource directory) and produces garbage.

### Mistake 2: Incorrect Ordinal Arithmetic

When resolving by name, the ordinal from `AddressOfNameOrdinals` is already a 0-based EAT index:
```asm
; CORRECT
movzx   eax, word [EOT + index * 2]     ; EAX = 0-based EAT index
mov     eax, [EAT + eax * 4]            ; EAT[ordinal]

; WRONG — subtracting Base is not needed when using name tables
movzx   eax, word [EOT + index * 2]
sub     eax, [export_dir + 0x10]        ; sub Base -- unnecessary, corrupts result
mov     eax, [EAT + eax * 4]
```

### Mistake 3: Not Accounting for Forwarders

On Windows 8+, resolving common APIs (VirtualAlloc, LoadLibraryA) from kernel32 may yield a forwarder string. Treating a forwarder RVA as a function address produces a crash:
```asm
; Without forwarder detection, func_va points to ASCII string "KERNELBASE.VirtualAlloc"
call    eax     ; CRASH — executing ASCII text
```

### Mistake 4: Hash Collision Causes Wrong Function

Hash collisions in the target export namespace return the wrong function. Always verify your chosen hash against the full export list of the target DLL before use. Use the Python script in Hash_Algorithms.md to pre-check for collisions.

### Mistake 5: Off-by-One in ENT Index to EOT Lookup

ENT and EOT are parallel arrays: `ENT[i]` and `EOT[i]` correspond to the same function. A common mistake after finding the matching hash at index `i` is to read `EOT[i-1]` or `EOT[i+1]` due to a decrement-before/after-compare confusion in count-down loops:
```asm
; WRONG (count-down loop error):
dec ecx              ; ECX becomes i-1
; ... hash matches with original i, but now ECX = i-1
movzx eax, word [EOT + ecx * 2]  ; reading EOT[i-1] instead of EOT[i]
```
