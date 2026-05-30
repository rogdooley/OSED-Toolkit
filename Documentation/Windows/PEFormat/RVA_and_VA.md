# RVA and VA — Definitive Reference for In-Memory PE Parsing

## Table of Contents

1. [The Three Address Spaces](#the-three-address-spaces)
2. [Why RVAs Exist](#why-rvas-exist)
3. [The One Shellcode Conversion: RVA to VA](#the-one-shellcode-conversion)
4. [How to Get the Actual ImageBase](#how-to-get-the-actual-imagebase)
5. [Where RVAs Appear in PE Structures](#where-rvas-appear-in-pe-structures)
6. [Assembly Pattern for Every Conversion](#assembly-pattern-for-every-conversion)
7. [ASLR and the ImageBase Mismatch](#aslr-and-the-imagebase-mismatch)
8. [Section-to-File-Offset Conversion](#section-to-file-offset-conversion)
9. [Alignment Rules](#alignment-rules)
10. [Range Validation](#range-validation)
11. [WinDbg Examples](#windbg-examples)
12. [Common Mistakes](#common-mistakes)
13. [Quick Reference](#quick-reference)

---

## The Three Address Spaces

Working with PE files requires clear thinking about three distinct address spaces. Confusing them is the most common source of incorrect PE parsing.

### 1. Virtual Address (VA)

A Virtual Address is a runtime memory address in the process's virtual address space. It is an absolute address — the actual number the CPU uses when executing instructions or dereferencing pointers.

Examples:
- `0x7C801A0B` — the VA of `VirtualAlloc` in kernel32.dll on Windows XP
- `0x7FFE0000` — the VA of the KUSER_SHARED_DATA page
- `0x00401000` — a typical VA for the `.text` section of an EXE's own code

VAs are what appear in register values during debugging. When WinDbg shows `eip=7c801a0b`, that is a VA.

VAs are meaningful only in context: the same VA in two different processes maps to different (or no) physical memory.

### 2. Relative Virtual Address (RVA)

An RVA is an offset from a module's actual load address (ImageBase). It is a relative quantity — a distance, not an absolute address.

```
RVA = VA - ImageBase (actual loaded base, not preferred)
VA  = ImageBase + RVA
```

Examples (kernel32.dll loaded at `0x7C800000` on XP):
- RVA `0x00001A0B` → VA `0x7C800000 + 0x00001A0B = 0x7C801A0B`
- RVA `0x000262C0` → VA `0x7C800000 + 0x000262C0 = 0x7C8262C0`

RVAs are what the PE format stores in its internal structures. Every pointer within a PE file — to code, to strings, to other structures — is expressed as an RVA from the module's base.

### 3. File Offset (Raw Offset)

A file offset is a byte position within the PE file on disk. It is an absolute position from the beginning of the file (byte 0 = first byte of the MZ header).

```
File offset 0x00000000 = IMAGE_DOS_HEADER.e_magic ('MZ')
File offset 0x0000003C = IMAGE_DOS_HEADER.e_lfanew
```

File offsets are used by:
- Hex editors viewing the PE file
- PE analysis tools (PEview, CFF Explorer, objdump)
- Custom PE parsers reading the file from disk

File offsets are **NOT** used by shellcode. Shellcode operates on the PE image as loaded into memory, not as stored on disk. In memory, sections are already mapped to their correct virtual addresses. File offsets into disk data are irrelevant.

### Comparison Table

```
Address Type      Source      Where Used               Absolute?
------------      ------      ----------               ---------
Virtual Address   Runtime     CPU, debugger, calls     Yes (in process context)
RVA               PE format   PE structure fields      No (relative to load base)
File Offset       PE file     Disk tools, raw parse    Yes (from file start)
```

---

## Why RVAs Exist

### Historical Context: The Base Address Problem

When Microsoft designed the Win32 PE format, they needed a solution to a specific problem: a DLL specifies a preferred load address (its `ImageBase` in the Optional Header), but that address might already be occupied by another module when the loader tries to map the DLL.

If all internal PE pointers were stored as absolute VAs using the preferred `ImageBase`, then any time the DLL had to load at a different address (called "rebasing"), every embedded pointer would need to be patched. This is expensive and requires the loader to enumerate every absolute pointer in the file.

RVAs solve this elegantly: every internal PE pointer is relative to "wherever the module base turns out to be." The loader reads an RVA, adds the actual load base, and gets the correct VA without any patching. The only addresses that need patching during rebasing are the ones stored in the Base Relocation Table — typically addresses that appear in the code or data sections as immediate operands (e.g., `mov eax, 0x10001234` where `0x10001234` is an absolute address to a global variable).

### The Modern Relevance: ASLR

Before Windows Vista, ASLR did not exist. System DLLs loaded at the same preferred address every boot (kernel32 always at `0x7C800000` on XP). The rebasing scenario was rare and mostly affected DLLs that had address collisions in multi-DLL processes.

With Windows Vista and later, Address Space Layout Randomization randomizes the load address of every module on every boot (and with high-entropy ASLR, every process creation). Every DLL load is now effectively a rebase. RVAs are not just a fallback mechanism — they are the design that makes ASLR possible without constant runtime patching of PE internals.

### What This Means for Shellcode

Shellcode cannot rely on hardcoded VAs for any system function:
- On XP (no ASLR): `kernel32!VirtualAlloc` might be at `0x7C8099A0` every time, but different service packs move it
- On Win7+ (ASLR): `kernel32!VirtualAlloc` is at a different address every boot

The solution: use RVA-based PE parsing at runtime to find the current VA. The PE export directory gives RVAs; adding the actual ImageBase (obtained from PEB walking) gives the correct current VA.

---

## The One Shellcode Conversion: RVA to VA

Shellcode performs exactly one type of address conversion: **RVA to VA**.

```
VA = ImageBase + RVA
```

where:
- `ImageBase` = actual loaded base of the module (from `LDR_DATA_TABLE_ENTRY.DllBase`, obtained via PEB walking)
- `RVA` = value read from a PE structure field

This conversion is applied every time the shellcode dereferences any pointer in a PE structure. It appears hundreds of times across shellcode source code, always as a single `ADD` instruction.

```nasm
; Template (appears constantly in PE parsing shellcode):
;   register = ImageBase + [ImageBase + offset_to_rva_field]

; Example 1: locate IMAGE_NT_HEADERS
mov  eax, [ebx + 0x3C]     ; eax = e_lfanew (an RVA)
add  eax, ebx               ; eax = NT headers VA  ← RVA→VA conversion

; Example 2: locate export directory
mov  edx, [eax + 0x78]     ; edx = export dir RVA (from DataDirectory[0])
add  edx, ebx               ; edx = export dir VA  ← RVA→VA conversion

; Example 3: locate a name string
mov  edi, [esi + ecx*4]    ; edi = name string RVA (from AddressOfNames[i])
add  edi, ebx               ; edi = name string VA  ← RVA→VA conversion

; Example 4: resolve function address
mov  eax, [edi + eax*4]    ; eax = function RVA (from AddressOfFunctions[i])
add  eax, ebx               ; eax = function VA  ← RVA→VA conversion
```

The pattern is always: read an RVA value, then `ADD EBX` (where EBX holds the module base).

---

## How to Get the Actual ImageBase

### Two Sources: One Correct, One Wrong

There are two places in a loaded PE image that contain a base address:

1. `IMAGE_OPTIONAL_HEADER.ImageBase` — the **preferred** base address embedded in the PE file
2. `LDR_DATA_TABLE_ENTRY.DllBase` — the **actual** loaded base address from the PEB

For shellcode, only source 2 is correct.

### Why OptionalHeader.ImageBase Is Wrong

Consider a DLL compiled with `ImageBase = 0x10000000`:
- At compile time, the linker stores `0x10000000` in `OptionalHeader.ImageBase`
- With ASLR, the loader decides to map the DLL at `0x62340000`
- The DLL is mapped at `0x62340000`; its sections are at `0x62341000`, etc.
- `OptionalHeader.ImageBase` still reads `0x10000000` — it was not updated
- `LDR_DATA_TABLE_ENTRY.DllBase` = `0x62340000` — the actual address

Using `OptionalHeader.ImageBase` as the base in RVA→VA conversions would give completely wrong addresses.

### The PEB Walking Chain

```
FS:[0x30]
    │
    └──► PEB (Process Environment Block)
              │
              └─[+0x0C]──► PEB_LDR_DATA
                                │
                                └─[+0x14]──► InInitializationOrderModuleList.Flink
                                                    │
                                                    └──► LDR_DATA_TABLE_ENTRY
                                                               │
                                                               └─[+0x08]── DllBase
                                                                           ← actual loaded base
```

Once PEB walking identifies the correct module (typically by comparing the DLL name or checking the export directory for a known function), `DllBase` is the value used as `ImageBase` in all subsequent RVA→VA conversions.

See `Documentation/Shellcode/PEB_Walking.md` for the full PEB walking implementation.

---

## Where RVAs Appear in PE Structures

The following is a complete catalog of RVA fields that shellcode and PE parsers encounter. Every one of these requires the `VA = ImageBase + RVA` conversion before dereferencing.

### IMAGE_DOS_HEADER

```
Field                  Offset  Type   Notes
-----                  ------  ----   -----
e_lfanew               +0x3C   DWORD  RVA → IMAGE_NT_HEADERS
                                      This is the only RVA in the DOS header.
                                      All other DOS header fields are file-format
                                      data not used by shellcode.
```

### IMAGE_NT_HEADERS / IMAGE_OPTIONAL_HEADER

```
Field                       Offset from     Type   Notes
                            OptHdr start
-----                       ------------    ----   -----
AddressOfEntryPoint         +0x10           DWORD  RVA → process/DLL entry point code
BaseOfCode                  +0x14           DWORD  RVA → start of .text section
BaseOfData                  +0x18           DWORD  RVA → start of .data section
                                                   (PE32 only; absent in PE32+)
DataDirectory[0].VA         +0x60           DWORD  RVA → export directory
DataDirectory[1].VA         +0x68           DWORD  RVA → import directory
DataDirectory[2].VA         +0x70           DWORD  RVA → resource directory
DataDirectory[3].VA         +0x78           DWORD  RVA → exception directory
DataDirectory[4].VA         +0x80           DWORD  RVA → security/certificate
DataDirectory[5].VA         +0x88           DWORD  RVA → base relocation table
DataDirectory[9].VA         +0xA8           DWORD  RVA → TLS directory
DataDirectory[12].VA        +0xC0           DWORD  RVA → import address table (IAT)
... (16 data directory entries total)
```

Note: for PE32+, DataDirectory starts at `+0x70` in the optional header, not `+0x60`.

### IMAGE_EXPORT_DIRECTORY

```
Field                   Offset  Type   Notes
-----                   ------  ----   -----
Name                    +0x0C   DWORD  RVA → DLL name string ("KERNEL32.dll\0")
AddressOfFunctions      +0x1C   DWORD  RVA → EAT (array of DWORD function RVAs)
AddressOfNames          +0x20   DWORD  RVA → ENPT (array of DWORD name string RVAs)
AddressOfNameOrdinals   +0x24   DWORD  RVA → EOT (array of WORD ordinals)

Each element of EAT:             DWORD  RVA → function code (or forwarder string)
Each element of ENPT:            DWORD  RVA → null-terminated function name string
```

### IMAGE_IMPORT_DESCRIPTOR

```
Field                   Offset  Type   Notes
-----                   ------  ----   -----
OriginalFirstThunk      +0x00   DWORD  RVA → Import Lookup Table (ILT)
Name                    +0x0C   DWORD  RVA → null-terminated DLL name string
FirstThunk              +0x10   DWORD  RVA → Import Address Table (IAT) for this DLL

Each ILT entry:                  DWORD  high bit: 0=name, 1=ordinal
                                         if 0: RVA → IMAGE_IMPORT_BY_NAME
                                         if 1: low 16 bits = ordinal number
```

### IMAGE_SECTION_HEADER

```
Field                   Offset  Type   Notes
-----                   ------  ----   -----
VirtualAddress          +0x0C   DWORD  RVA → section start in memory
                                        (use: base + VirtualAddress = section VA)
PointerToRawData        +0x14   DWORD  File offset (NOT an RVA)
                                        Used only for on-disk PE analysis
```

### IMAGE_THUNK_DATA (ILT/IAT entries)

```
When bit 31 = 0 (name import):
  [30:0] = DWORD  RVA → IMAGE_IMPORT_BY_NAME structure
                         which contains:
                           +0x00  WORD  Hint (ordinal hint, may be ignored)
                           +0x02  CHAR[] null-terminated function name

When bit 31 = 1 (ordinal import):
  [15:0] = import ordinal number (external ordinal, needs Base adjustment)
```

---

## Assembly Pattern for Every Conversion

The pattern `add reg, base_reg` appears after every RVA read. Here it is applied systematically through a PE walk:

```nasm
; ============================================================
; Complete PE header navigation with RVA→VA at each step
; Input: EBX = module base address (DllBase from PEB walk)
; ============================================================

    ; --- Navigate to IMAGE_NT_HEADERS ---
    mov  eax, [ebx + 0x3C]         ; eax = e_lfanew RVA
    add  eax, ebx                   ; eax = NT headers VA
                                    ; ← RVA→VA conversion #1

    ; --- Find export directory ---
    mov  edx, [eax + 0x78]         ; edx = export dir RVA (NT+0x18+0x60)
    add  edx, ebx                   ; edx = export dir VA
                                    ; ← RVA→VA conversion #2

    ; --- Load AddressOfNames (ENPT) ---
    mov  edi, [edx + 0x20]         ; edi = ENPT RVA
    add  edi, ebx                   ; edi = ENPT VA
                                    ; ← RVA→VA conversion #3

    ; --- Load AddressOfNameOrdinals (EOT) ---
    mov  esi, [edx + 0x24]         ; esi = EOT RVA
    add  esi, ebx                   ; esi = EOT VA
                                    ; ← RVA→VA conversion #4

    ; --- Load AddressOfFunctions (EAT) ---
    mov  ecx, [edx + 0x1C]         ; ecx = EAT RVA
    add  ecx, ebx                   ; ecx = EAT VA
                                    ; ← RVA→VA conversion #5

    ; --- Resolve individual name string ---
    ; (in loop body, ECX = name index)
    mov  eax, [edi + ecx*4]        ; eax = name string RVA (from ENPT[ecx])
    add  eax, ebx                   ; eax = name string VA
                                    ; ← RVA→VA conversion #6 (per-iteration)
    ; eax now points to the null-terminated function name

    ; --- Resolve function VA ---
    ; (after match found; EDI = func_index from EOT)
    mov  eax, [ecx + edi*4]        ; eax = function RVA (from EAT[edi])
    add  eax, ebx                   ; eax = function VA  ← callable address
                                    ; ← RVA→VA conversion #7
```

The invariant across every shellcode's PE parsing code: **EBX holds the module base, and every RVA immediately gets `add ..., ebx` applied**.

---

## ASLR and the ImageBase Mismatch

### What ASLR Does

Address Space Layout Randomization (introduced in Windows Vista) randomizes the base address of modules (EXEs and DLLs) when they are loaded. The randomization occurs at load time, with the degree of entropy depending on the Windows version and whether high-entropy ASLR is enabled.

```
Without ASLR (Windows XP):
  kernel32.dll always loads at 0x7C800000
  ntdll.dll    always loads at 0x7C900000
  Shellcode could hardcode: mov eax, 0x7C800000  ← "works" but fragile

With ASLR (Windows Vista and later):
  kernel32.dll loads at: 0x76890000 (one boot)
                          0x75A20000 (next boot)
                          0x77BB0000 (another boot)
  No hardcoded address is valid.
  PEB walking is required to find the actual base.
```

### The OptionalHeader.ImageBase Trap

The `OptionalHeader.ImageBase` field reflects what the linker *intended* as the load address — it is written at compile time and is not updated when the module is rebased.

```
DLL compiled with: ImageBase = 0x10000000
ASLR loads it at:             0x62A40000

PE image in memory at 0x62A40000:
  [0x62A40000 + 0x3C] = e_lfanew = 0x00000108
  [0x62A40000 + 0x108 + 0x1C] = OptionalHeader.ImageBase = 0x10000000
                                                            ← stale!

LDR_DATA_TABLE_ENTRY.DllBase = 0x62A40000   ← correct

If shellcode uses OptionalHeader.ImageBase for RVA→VA:
  export_dir_va = 0x10000000 + export_dir_rva
                = 0x10003C40  (or wherever)
  ← This address is either unmapped or belongs to a different module.
  ← Reading it causes an access violation or reads wrong data.
```

### The Base Relocation Table

To support rebasing, DLLs contain a Base Relocation Table (`DataDirectory[5]`). This table lists every location in the DLL's code and data sections where an absolute VA was embedded at link time (e.g., as an immediate value in an instruction or as an entry in a jump table).

When the loader maps the DLL at a non-preferred base, it applies delta = `(actual_base - preferred_base)` to every listed address. This patching fixes embedded absolute addresses.

RVAs in PE structures do NOT appear in the relocation table — they are correct by definition at any load address.

After loading, the patched DLL's code is correct for the actual load address. The `OptionalHeader.ImageBase` value is just a stale artifact; the actual base is in `LDR_DATA_TABLE_ENTRY.DllBase`.

### Base Relocation Table Format (for completeness)

```c
// Relocation block header
typedef struct _IMAGE_BASE_RELOCATION {
    DWORD VirtualAddress;    // RVA of the 4KB page this block covers
    DWORD SizeOfBlock;       // total size of this block (header + entries)
    // WORD TypeOffset[...]; // array of 16-bit entries following the header
} IMAGE_BASE_RELOCATION;

// Each 16-bit entry:
// [15:12] = type  (0=pad, 3=HIGHLOW/32-bit patch, 10=DIR64/64-bit patch)
// [11:0]  = offset from block's VirtualAddress
//           final patching target = base + VirtualAddress + offset
```

This is relevant for shellcode that needs to avoid triggering integrity checks, not for typical API resolution.

---

## Section-to-File-Offset Conversion

This conversion is NOT used by shellcode operating on in-memory PE images. It is used by PE analysis tools that parse the PE file from a file buffer.

### The Problem

When a PE file is mapped from disk into a buffer (e.g., with `fread`), it is not mapped the same way the loader maps it. The loader maps each section at its `VirtualAddress` relative to the load base, with proper alignment. A raw file read just concatenates the sections as they appear on disk.

In a raw file buffer, sections are at `PointerToRawData` offsets, not at `VirtualAddress` offsets.

### The Algorithm

```
For a given RVA, find which section contains it, then:

file_offset = RVA - section.VirtualAddress + section.PointerToRawData

Where the correct section satisfies:
  section.VirtualAddress <= RVA < (section.VirtualAddress + section.VirtualSize)
```

Pseudocode:

```python
def rva_to_file_offset(rva, section_headers):
    """
    Convert an RVA to a file offset in the raw PE file.
    Only needed when parsing a PE from a file buffer (not in-memory image).
    
    Args:
        rva: Relative Virtual Address to convert
        section_headers: list of (VirtualAddress, VirtualSize, PointerToRawData)
    
    Returns:
        File offset, or None if RVA is not in any section
    """
    for va, vsize, raw_ptr in section_headers:
        if va <= rva < (va + vsize):
            return rva - va + raw_ptr
    return None  # RVA not found in any section
```

### Why Shellcode Never Does This

Shellcode operates on the PE image as loaded into the process's virtual memory by the Windows loader. In that mapping:
- The image starts at `DllBase` (e.g., `0x7C800000`)
- Each section is already mapped at its `VirtualAddress` relative to `DllBase`
- Converting RVA to VA is simply `VA = DllBase + RVA`
- File offsets are meaningless — sections are at their VirtualAddress positions, not PointerToRawData positions

The distinction matters for tool development but is irrelevant to shellcode execution.

---

## Alignment Rules

### Two Alignment Boundaries

The PE Optional Header specifies two alignment values that govern how the image is laid out in memory vs. on disk.

```
OptionalHeader.SectionAlignment  (typically 0x1000 = 4096 bytes = one page)
  → Sections are mapped in memory on this boundary
  → Every section's VA is a multiple of SectionAlignment

OptionalHeader.FileAlignment     (typically 0x200 = 512 bytes = one sector)
  → Sections are stored in the file on this boundary
  → Every section's PointerToRawData is a multiple of FileAlignment
```

### Example: A Section With VirtualSize = 0x1800

```
In memory (SectionAlignment = 0x1000):
  VirtualAddress = 0x1000
  Bytes 0x1000–0x27FF: actual section content (0x1800 bytes)
  Bytes 0x2800–0x2FFF: zero padding (to next 0x1000 boundary)
  Next section starts at 0x3000

On disk (FileAlignment = 0x200):
  PointerToRawData = 0x400
  Bytes 0x400–0x19FF: section content
  Bytes 0x1A00–0x1BFF: possible padding to 0x200 boundary
  SizeOfRawData = 0x1A00 (aligned up from VirtualSize 0x1800)
```

### Why This Matters for Shellcode

It generally does not matter. Shellcode works with the in-memory image, where:
- `VA = base + RVA` is always correct
- Alignment is already handled by the loader
- The VirtualSize vs. aligned-in-memory distinction only matters if reading past the VirtualSize into the padding region (which returns zeros, not meaningful data)

The alignment rules matter when:
- Writing a PE parser that processes files from disk
- Manually reconstructing a PE from memory (e.g., for DLL injection or PE dumping)
- Analyzing why a file-on-disk parsing tool gives different results than in-memory analysis

---

## Range Validation

### Why Validate

Malformed PEs (from corruption, obfuscation, packing, or intentional anti-analysis) may have RVA fields with out-of-range values. Dereferencing an invalid RVA causes an access violation that crashes the shellcode.

For exploitation shellcode targeting a specific DLL, validation adds code size without benefit — system DLLs are not malformed. For general-purpose shellcode (e.g., injected into arbitrary processes), basic validation prevents crashes.

### The SizeOfImage Check

The simplest useful validation: any RVA that is `>= SizeOfImage` points outside the mapped image and is invalid.

```nasm
; EBX = module base
; EAX = e_lfanew (already loaded)
; EDX = candidate RVA to validate

; Load SizeOfImage from OptionalHeader
mov  ecx, [ebx + eax + 0x50]   ; OptHdr.SizeOfImage at offset 0x50 from NT headers
                                 ; (0x18 for OptHdr start + 0x38 for SizeOfImage field
                                 ;  = 0x50 from NT header start)
cmp  edx, ecx                   ; rva >= SizeOfImage?
jae  rva_is_invalid             ; yes → reject
; Otherwise, safe to use: base + rva is within mapped image
```

### Checking Against Data Directory Bounds

For export directory traversal specifically, validating that the export directory itself is within bounds:

```nasm
; Load export dir RVA and size
mov  ecx, [ebx + eax + 0x78]   ; export dir RVA
mov  edx, [ebx + eax + 0x7C]   ; export dir size

; Validate: export dir RVA must be > 0 and within image
test ecx, ecx
jz   no_export_dir              ; RVA = 0 → no export directory

mov  esi, [ebx + eax + 0x50]   ; SizeOfImage
cmp  ecx, esi
jae  corrupt_pe                 ; export dir past end of image

; Validate export dir does not extend past image
add  edx, ecx                   ; export_dir_end RVA
cmp  edx, esi
ja   corrupt_pe                 ; export dir extends past end of image
```

---

## WinDbg Examples

### Verifying Load Address vs. Preferred Base

```
; On Windows XP (no ASLR):
0:000> lm m kernel32
start    end      module name
7c800000 7c8f6000 kernel32

; Preferred base from PE header:
0:000> dd 7c800000+3c L1
7c80003c  000000e8        ; e_lfanew = 0xE8

0:000> dd 7c800000+e8+1c L1    ; OptHdr.ImageBase at 0x18+0x04 = 0x1C from NT headers
7c8000e8+1c ...
; Actually: OptHdr starts at NT+0x18; ImageBase at OptHdr+0x1C = NT+0x34
0:000> dd 7c800000+e8+34 L1
7c80011c  7c800000        ; Preferred ImageBase = 0x7C800000 (matches actual on XP)

; On Windows 10 with ASLR:
0:000> lm m kernel32
start             end               module name
00007ff9e4a00000  00007ff9e4bc0000  KERNEL32

; Preferred base in PE header (64-bit, ImageBase at OptHdr+0x18 = NT+0x30):
0:000> dq kernel32+3c L1
→ e_lfanew = 0x108 (example)
0:000> dq kernel32+108+30 L1
→ ImageBase in header = 0x0000000180000000  (or similar linker default)
← actual load = 0x7FF9E4A00000 ← very different
```

### Computing Entry Point VA

```
; kernel32 loaded at base = 0x7C800000 (XP example)

; Step 1: find e_lfanew
0:000> dd 7c800000+3c L1
7c80003c  000000e8

; Step 2: AddressOfEntryPoint is at OptHdr+0x10 = NT+0x28
0:000> dd 7c800000+e8+28 L1
7c800110  0001f690        ; ep_rva = 0x0001F690

; Step 3: entry point VA = base + rva
0:000> u 7c800000+1f690
7c81f690 8bff            mov     edi,edi
7c81f692 55              push    ebp
7c81f694 8bec            mov     ebp,esp
; (DLL entry point boilerplate — not VirtualAlloc, just DllMain)

; Confirm with symbol:
0:000> ln 7c81f690
(7c81f690)   kernel32!_DllMainCRTStartup
```

### RVA Arithmetic During Export Resolution

```
; Follow export directory RVA→VA in one step:
0:000> dd 7c800000+e8+78 L2
...  000262c0 00007740
; export_dir_rva = 0x262C0, size = 0x7740

; Verify export dir VA:
0:000> dt ntdll!_IMAGE_EXPORT_DIRECTORY 7c800000+262c0
; (shows all fields with correct values)

; Manual RVA→VA for AddressOfFunctions:
0:000> dd 7c800000+262c0+1c L1  ; AddressOfFunctions field
→ eat_rva = 0x00026940

0:000> dd 7c800000+26940 L8     ; first 8 EAT entries
7c826940  000195e0 0001a680 ...
; Each is a function RVA. First function VA = 0x7C800000 + 0x000195E0 = 0x7C8195E0

0:000> u 7c8195e0
7c8195e0 ...           ; should be the ordinal-1 export of kernel32
0:000> ln 7c8195e0     ; confirms which function
```

---

## Common Mistakes

### Mistake 1: Adding ImageBase Twice

This is the most common error for beginners. The shellcode already has the module base from PEB walking and correctly uses it for initial navigation — but then forgets and adds it again.

**Wrong**:
```nasm
; EBX = DllBase from PEB walk (correct, e.g., 0x7C800000)
mov  eax, [ebx + 0x3C]         ; eax = e_lfanew
mov  edx, [ebx + eax + 0x78]   ; edx = export dir RVA
add  edx, ebx                   ; edx = export dir VA (correct)

; Now loading AddressOfNames:
mov  esi, [edx + 0x20]         ; esi = ENPT RVA  (correct so far)
; ← BUT if we now do: mov esi, [ebx+original_imagbase+esi]
; or confusingly use OptionalHeader.ImageBase somewhere, we add base twice
mov  eax, [ebx + eax + 0x1C]   ; ← uses e_lfanew (in eax) again, not intentional
```

**Correct**:
Keep one register (`EBX`) as the module base throughout. Apply `ADD EBX` exactly once per RVA, immediately after loading it.

### Mistake 2: Using File Offsets as RVAs When Parsing from a Buffer

**Wrong scenario**:
```python
# Reading PE from disk into a buffer (bad approach):
with open("kernel32.dll", "rb") as f:
    pe_data = f.read()

# Treating the file buffer as a memory-mapped image:
e_lfanew = struct.unpack_from("<I", pe_data, 0x3C)[0]
# e_lfanew = 0xE8 — this is correct, e_lfanew is an RVA

export_rva = struct.unpack_from("<I", pe_data, e_lfanew + 0x78)[0]
# export_rva = 0x262C0 — correct

# WRONG: treating pe_data as a mapped image:
export_dir_offset = export_rva   # 0x262C0 as a file offset
export_dir_data = pe_data[export_dir_offset:]
# pe_data[0x262C0] is NOT where the export directory is in the file on disk!
# Because sections use PointerToRawData, not VirtualAddress, as file offsets.
```

**Correct**: Use the RVA→file-offset conversion algorithm (see [Section-to-File-Offset Conversion](#section-to-file-offset-conversion)) or use a PE parsing library that handles the mapping.

### Mistake 3: Hardcoding Section Offsets

**Wrong**:
```nasm
; Assuming .text is always at base + 0x1000:
mov  esi, ebx
add  esi, 0x1000    ; "everybody puts .text at 0x1000, right?"
; ← Wrong for any DLL where .text is at a different RVA
; ← Wrong for any DLL with a header padding section before .text
; ← Wrong on 64-bit where alignment may differ
```

**Correct**: Always navigate from the PE headers. Read `IMAGE_SECTION_HEADER.VirtualAddress` for the actual section RVA.

### Mistake 4: Off-by-One in Section Range Check

**Wrong**:
```c
// Checking if RVA is in a section:
if (rva >= sec.VirtualAddress && rva <= sec.VirtualAddress + sec.VirtualSize) {
    // ← <= includes the byte AFTER the last byte of the section
}
```

**Correct**:
```c
if (rva >= sec.VirtualAddress && rva < sec.VirtualAddress + sec.VirtualSize) {
    // ← strict less-than: [VirtualAddress, VirtualAddress + VirtualSize)
}
```

The last valid byte in the section is at `VirtualAddress + VirtualSize - 1`. The byte at `VirtualAddress + VirtualSize` belongs to the next section or alignment padding.

### Mistake 5: Forgetting to Validate That an RVA Field Is Non-Zero

The export directory RVA field is `0x00000000` for DLLs/EXEs that have no exports (e.g., a resource-only DLL, or an EXE that exports nothing). Adding the module base to RVA `0` gives `module_base` — which is the start of the MZ header. Reading the export directory structure from the MZ header gives garbage values. All subsequent parsing will be wrong and will likely crash.

**Correct**:
```nasm
mov  edx, [ebx + eax + 0x78]   ; export dir RVA
test edx, edx
jz   no_exports                 ; RVA = 0 → skip this module
add  edx, ebx                   ; export dir VA
```

---

## Quick Reference

```
Conversion:
  VA  = ImageBase + RVA
  RVA = VA - ImageBase

ImageBase to use:
  LDR_DATA_TABLE_ENTRY.DllBase (actual, correct)
  NOT OptionalHeader.ImageBase (preferred, stale with ASLR)

Key offsets (from module base):
  [base + 0x00]           = 'MZ' magic
  [base + 0x3C]           = e_lfanew (RVA → NT headers)
  [base + e_lfanew + 0x78] = export dir RVA  (PE32)
  [base + e_lfanew + 0x7C] = export dir size (PE32)
  [base + e_lfanew + 0x88] = export dir RVA  (PE32+/64-bit)
  [base + e_lfanew + 0x50] = SizeOfImage (for range validation)

RVA→VA in assembly:
  mov  eax, [ebx + some_offset]   ; load RVA
  add  eax, ebx                   ; convert to VA  ← one ADD every time

ASLR impact:
  PE header's ImageBase: stale (compile-time preferred value)
  LDR_DATA_TABLE_ENTRY.DllBase: actual current base
  PEB walk → LDR → DllBase → use this for all RVA→VA conversions

File offset vs RVA:
  File offset = position in .dll/.exe file on disk
  RVA = offset from module base in memory
  In memory: VA = base + RVA  (always)
  From disk file: requires section table lookup (not needed in shellcode)
```
