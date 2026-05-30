# IMAGE_NT_HEADERS — NT Headers Reference for Exploit Development

## Table of Contents

1. [Purpose and Structure Overview](#purpose-and-structure-overview)
2. [PE Signature](#pe-signature)
3. [IMAGE_FILE_HEADER — All 7 Fields](#image_file_header--all-7-fields)
4. [IMAGE_OPTIONAL_HEADER — PE32 vs PE32+](#image_optional_header--pe32-vs-pe32)
5. [Key Optional Header Fields: Deep Dive](#key-optional-header-fields-deep-dive)
6. [DataDirectory Array](#datadirectory-array)
7. [x86 vs x64 Differences](#x86-vs-x64-differences)
8. [Assembly Traversal](#assembly-traversal)
9. [WinDbg Verification](#windbg-verification)
10. [Common Mistakes](#common-mistakes)
11. [Exploit and Shellcode Relevance](#exploit-and-shellcode-relevance)

---

## Purpose and Structure Overview

IMAGE_NT_HEADERS is the core of the PE file format. After the loader validates the DOS header and
reads `e_lfanew`, it jumps to IMAGE_NT_HEADERS to determine everything about how to load and map
the file: target architecture, memory requirements, section layout, entry point, and the locations
of all data directories (exports, imports, relocations, TLS, etc.).

For shellcode writers, IMAGE_NT_HEADERS is the gateway to the export directory, which is required
for hash-based API resolution — the technique used by virtually every piece of position-independent
shellcode to locate Windows API functions without hardcoded addresses.

### Top-Level Layout

```
IMAGE_NT_HEADERS (PE32):
  +0x00  Signature          DWORD               "PE\0\0" = 0x00004550
  +0x04  FileHeader         IMAGE_FILE_HEADER   20 bytes
  +0x18  OptionalHeader     IMAGE_OPTIONAL_HEADER32  224 bytes (standard)

IMAGE_NT_HEADERS64 (PE32+):
  +0x00  Signature          DWORD               "PE\0\0" = 0x00004550
  +0x04  FileHeader         IMAGE_FILE_HEADER   20 bytes (identical)
  +0x18  OptionalHeader     IMAGE_OPTIONAL_HEADER64  240 bytes
```

The Signature and FileHeader are identical between PE32 and PE32+. Only the OptionalHeader differs.
The OptionalHeader's `Magic` field (first 2 bytes) tells you which variant you have.

**C structure definition**:

```c
typedef struct _IMAGE_NT_HEADERS {
    DWORD                   Signature;          // +0x00
    IMAGE_FILE_HEADER       FileHeader;         // +0x04
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;     // +0x18
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

typedef struct _IMAGE_NT_HEADERS64 {
    DWORD                   Signature;          // +0x00
    IMAGE_FILE_HEADER       FileHeader;         // +0x04
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;     // +0x18
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;
```

---

## PE Signature

| Field       | Offset | Size  | Value      | Description                      |
|-------------|--------|-------|------------|----------------------------------|
| `Signature` | +0x00  | DWORD | 0x00004550 | "PE\0\0" — PE file magic number |

The 4-byte signature `PE\0\0` marks the start of IMAGE_NT_HEADERS. In raw bytes (little-endian
storage): `50 45 00 00`.

- 0x50 = 'P'
- 0x45 = 'E'
- 0x00 = null byte
- 0x00 = null byte

The Windows loader reads this DWORD immediately after jumping to `base + e_lfanew`. If the value
does not equal `0x00004550`, loading fails with `STATUS_INVALID_IMAGE_FORMAT`.

For shellcode: always verify this signature before reading FileHeader or OptionalHeader fields.
A bad `e_lfanew` combined with no signature check will cause a misparse or crash.

```nasm
; Shellcode signature check:
; EAX = base + e_lfanew (already computed)
cmp dword [eax], 0x00004550    ; "PE\0\0"
jne .not_a_pe_module
```

---

## IMAGE_FILE_HEADER — All 7 Fields

IMAGE_FILE_HEADER is a 20-byte structure at offset +0x04 within IMAGE_NT_HEADERS. It describes
the machine architecture and basic file properties. It is identical between PE32 and PE32+.

```c
typedef struct _IMAGE_FILE_HEADER {
    WORD    Machine;                // +0x04 (from NT headers base)
    WORD    NumberOfSections;       // +0x06
    DWORD   TimeDateStamp;          // +0x08
    DWORD   PointerToSymbolTable;   // +0x0C
    DWORD   NumberOfSymbols;        // +0x10
    WORD    SizeOfOptionalHeader;   // +0x14
    WORD    Characteristics;        // +0x16
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
```

Offsets above are from the start of IMAGE_FILE_HEADER. From IMAGE_NT_HEADERS base, add 0x04.

### Full Field Table

| Field                  | Offset from FileHeader | Offset from NT Headers | Size  |
|------------------------|------------------------|------------------------|-------|
| `Machine`              | +0x00                  | +0x04                  | WORD  |
| `NumberOfSections`     | +0x02                  | +0x06                  | WORD  |
| `TimeDateStamp`        | +0x04                  | +0x08                  | DWORD |
| `PointerToSymbolTable` | +0x08                  | +0x0C                  | DWORD |
| `NumberOfSymbols`      | +0x0C                  | +0x10                  | DWORD |
| `SizeOfOptionalHeader` | +0x10                  | +0x14                  | WORD  |
| `Characteristics`      | +0x12                  | +0x16                  | WORD  |

---

### `Machine` — Architecture Identifier

**Offset from FileHeader**: +0x00 | **Type**: WORD

The Machine field identifies the target processor architecture. The PE loader validates that the
machine type matches the running system before proceeding.

| Value    | Constant                       | Architecture                         |
|----------|--------------------------------|--------------------------------------|
| `0x014C` | IMAGE_FILE_MACHINE_I386        | x86 (32-bit Intel / AMD)             |
| `0x8664` | IMAGE_FILE_MACHINE_AMD64       | x64 (64-bit Intel / AMD, "x86-64")   |
| `0x01C4` | IMAGE_FILE_MACHINE_ARMNT       | ARM Thumb-2 (32-bit ARM, NT)         |
| `0xAA64` | IMAGE_FILE_MACHINE_ARM64       | AArch64 (64-bit ARM)                 |
| `0x0200` | IMAGE_FILE_MACHINE_IA64        | Intel Itanium (64-bit, legacy)       |
| `0x0000` | IMAGE_FILE_MACHINE_UNKNOWN     | Architecture unknown / any           |
| `0x01F0` | IMAGE_FILE_MACHINE_POWERPC     | PowerPC (legacy Windows NT/CE)       |
| `0x0162` | IMAGE_FILE_MACHINE_R3000       | MIPS (legacy)                        |
| `0x0168` | IMAGE_FILE_MACHINE_R10000      | MIPS R10000 (legacy)                 |

**For shellcode**: If you are writing x86 shellcode targeting Windows 10 x64 in a WoW64 process,
the kernel32.dll loaded in the WoW64 environment has `Machine = 0x014C`. The native 64-bit
kernel32.dll (in SysWOW64) has `Machine = 0x8664`. When writing architecture-adaptive shellcode,
check this field to determine pointer sizes and header offsets.

---

### `NumberOfSections` — Section Count

**Offset from FileHeader**: +0x02 | **Type**: WORD

Counts the number of IMAGE_SECTION_HEADER structures that follow the OptionalHeader. The section
table begins immediately after the OptionalHeader at:

```
sections_start = base + e_lfanew + 0x04 + sizeof(IMAGE_FILE_HEADER) + SizeOfOptionalHeader
               = base + e_lfanew + 0x18 + SizeOfOptionalHeader
```

**Shellcode relevance**: Typically not needed for export resolution (which uses the DataDirectory
RVA directly). However, shellcode that manually maps a PE or injects a PE section by section needs
this value to iterate the section headers.

**Typical values**: 3–8 sections for compiled binaries; 1–2 for hand-assembled shellcode payloads;
up to 96 sections are permitted by the specification.

---

### `TimeDateStamp` — Build Timestamp

**Offset from FileHeader**: +0x04 | **Type**: DWORD

A 32-bit Unix timestamp (seconds since January 1, 1970 UTC) recording when the linker produced
this PE file. Not validated by the Windows PE loader.

**Forensic importance**: The TimeDateStamp was historically a reliable build date indicator used
by security researchers to track malware campaign timelines, correlate samples, and attribute
threat actors. It appears in both the file header and the export directory.

**Malware evasion**: Many modern malware families and packers zero this field or set it to a
plausible-but-fake timestamp to defeat timeline analysis. Some tools (MSVC with `/Brepro` flag)
intentionally set it to a hash of the binary content to enable reproducible builds.

**WinDbg**: `.formats <timestamp_value>` converts the DWORD to a human-readable date.

---

### `PointerToSymbolTable` and `NumberOfSymbols`

**Offsets**: +0x08 and +0x0C | **Type**: DWORD each

These fields supported the old COFF symbol table format used during linking. In production PE
binaries (both debug and release builds), the symbol table is not embedded in the PE file —
symbols live in separate `.pdb` files. Both fields are always 0 in release builds and almost
always 0 in debug builds.

**Shellcode**: Ignore these fields completely.

---

### `SizeOfOptionalHeader` — Dynamic Structure Size

**Offset from FileHeader**: +0x10 | **Type**: WORD

Specifies the size in bytes of the IMAGE_OPTIONAL_HEADER structure that follows. The PE loader
uses this field rather than a compiled `sizeof()` constant for a critical reason: it allows
future PE format extensions to add fields without breaking older loaders.

**Standard values**:
- PE32 (x86): `0x00E0` (224 bytes)
- PE32+ (x64): `0x00F0` (240 bytes)

**Why this matters for shellcode**: When computing the address of the section table (which follows
the optional header), you must use this field:

```nasm
; EAX = base of IMAGE_FILE_HEADER
; Compute start of section table:
movzx ecx, word [eax + 0x10]   ; SizeOfOptionalHeader
lea   edx, [eax + 0x12 + 2]    ; start of OptionalHeader (FileHeader base + 0x14 + 0x04 adjustment)
; Actually: section_table = NT_headers_base + 0x18 + SizeOfOptionalHeader
```

More clearly:
```nasm
; EBX = NT headers base (base + e_lfanew)
movzx ecx, word [ebx + 0x14]       ; SizeOfOptionalHeader (at NT+0x04+0x10 = NT+0x14)
lea   eax, [ebx + 0x18]            ; start of OptionalHeader
add   eax, ecx                     ; start of section table
; EAX now points to first IMAGE_SECTION_HEADER
```

A hardcoded offset to the section table will break for non-standard builds.

---

### `Characteristics` — File Attribute Flags

**Offset from FileHeader**: +0x12 | **Type**: WORD

A bitmask of flags describing the file. Key values:

| Bit (Value) | Constant                              | Meaning                                   |
|-------------|---------------------------------------|-------------------------------------------|
| 0x0001      | IMAGE_FILE_RELOCS_STRIPPED            | No relocation info (must load at ImageBase)|
| 0x0002      | IMAGE_FILE_EXECUTABLE_IMAGE           | File is an executable (not an object file)|
| 0x0004      | IMAGE_FILE_LINE_NUMS_STRIPPED         | Line numbers stripped (always in release) |
| 0x0008      | IMAGE_FILE_LOCAL_SYMS_STRIPPED        | Local symbols stripped (always in release)|
| 0x0020      | IMAGE_FILE_LARGE_ADDRESS_AWARE        | App handles >2GB addresses (x64 flag)     |
| 0x0100      | IMAGE_FILE_32BIT_MACHINE              | 32-bit word machine (set for x86 PE32)    |
| 0x0200      | IMAGE_FILE_DEBUG_STRIPPED             | Debug info removed                        |
| 0x0400      | IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP    | Copy to swap if on removable media        |
| 0x0800      | IMAGE_FILE_NET_RUN_FROM_SWAP          | Copy to swap if on network                |
| 0x1000      | IMAGE_FILE_SYSTEM                     | System file (driver), not user-mode app   |
| 0x2000      | IMAGE_FILE_DLL                        | File is a DLL (not standalone EXE)        |
| 0x4000      | IMAGE_FILE_UP_SYSTEM_ONLY             | Run only on uniprocessor machines         |

**DLL vs EXE detection**:
- `Characteristics & 0x2000` is set for DLLs, clear for EXEs.
- This is how the Windows loader determines if `DllMain` should be called.

**ASLR-related**: The absence of `IMAGE_FILE_RELOCS_STRIPPED` (bit 0x0001) combined with a
relocation directory means the loader can rebase the image — prerequisite for ASLR. If
`IMAGE_FILE_RELOCS_STRIPPED` is set, the image MUST load at its preferred `ImageBase`.

**Shellcode relevance**: When injecting a PE payload, check this field to know whether the
payload is an EXE or DLL and set up the call accordingly (call DllMain vs transfer to entry point).

---

## IMAGE_OPTIONAL_HEADER — PE32 vs PE32+

Despite the name, the "optional" header is mandatory in all PE executables and DLLs. The name
is a historical artifact from COFF object files, where the optional header genuinely was optional.

### PE32 (IMAGE_OPTIONAL_HEADER32) — x86

```c
typedef struct _IMAGE_OPTIONAL_HEADER {
    // Standard fields (COFF)
    WORD    Magic;                      // +0x00  0x010B for PE32
    BYTE    MajorLinkerVersion;         // +0x02
    BYTE    MinorLinkerVersion;         // +0x03
    DWORD   SizeOfCode;                 // +0x04
    DWORD   SizeOfInitializedData;      // +0x08
    DWORD   SizeOfUninitializedData;    // +0x0C
    DWORD   AddressOfEntryPoint;        // +0x10  RVA
    DWORD   BaseOfCode;                 // +0x14  RVA
    DWORD   BaseOfData;                 // +0x18  RVA (PE32 only, absent in PE32+)
    // Windows-specific fields
    DWORD   ImageBase;                  // +0x1C  Preferred load VA (32-bit in PE32)
    DWORD   SectionAlignment;           // +0x20
    DWORD   FileAlignment;              // +0x24
    WORD    MajorOperatingSystemVersion;// +0x28
    WORD    MinorOperatingSystemVersion;// +0x2A
    WORD    MajorImageVersion;          // +0x2C
    WORD    MinorImageVersion;          // +0x2E
    WORD    MajorSubsystemVersion;      // +0x30
    WORD    MinorSubsystemVersion;      // +0x32
    DWORD   Win32VersionValue;          // +0x34  Reserved, must be 0
    DWORD   SizeOfImage;                // +0x38
    DWORD   SizeOfHeaders;              // +0x3C
    DWORD   CheckSum;                   // +0x40
    WORD    Subsystem;                  // +0x44
    WORD    DllCharacteristics;         // +0x46
    DWORD   SizeOfStackReserve;         // +0x48
    DWORD   SizeOfStackCommit;          // +0x4C
    DWORD   SizeOfHeapReserve;          // +0x50
    DWORD   SizeOfHeapCommit;           // +0x54
    DWORD   LoaderFlags;                // +0x58  Reserved, must be 0
    DWORD   NumberOfRvaAndSizes;        // +0x5C  Count of DataDirectory entries
    IMAGE_DATA_DIRECTORY DataDirectory[16]; // +0x60  8 bytes each × 16 = 128 bytes
} IMAGE_OPTIONAL_HEADER32;
// Total size: 0x60 + 0x80 = 0xE0 (224 bytes)
```

### PE32+ (IMAGE_OPTIONAL_HEADER64) — x64

The PE32+ optional header differs in three ways:
1. `BaseOfData` field is **removed** (it would have been at +0x18)
2. `ImageBase` is **expanded from DWORD to ULONGLONG** (64-bit)
3. `SizeOfStackReserve`, `SizeOfStackCommit`, `SizeOfHeapReserve`, `SizeOfHeapCommit` are each
   **expanded from DWORD to ULONGLONG**

```c
typedef struct _IMAGE_OPTIONAL_HEADER64 {
    WORD        Magic;                      // +0x00  0x020B for PE32+
    BYTE        MajorLinkerVersion;         // +0x02
    BYTE        MinorLinkerVersion;         // +0x03
    DWORD       SizeOfCode;                 // +0x04
    DWORD       SizeOfInitializedData;      // +0x08
    DWORD       SizeOfUninitializedData;    // +0x0C
    DWORD       AddressOfEntryPoint;        // +0x10  RVA (still DWORD)
    DWORD       BaseOfCode;                 // +0x14  RVA (still DWORD)
    // NOTE: No BaseOfData field here
    ULONGLONG   ImageBase;                  // +0x18  64-bit preferred load VA
    DWORD       SectionAlignment;           // +0x20
    DWORD       FileAlignment;              // +0x24
    WORD        MajorOperatingSystemVersion;// +0x28
    WORD        MinorOperatingSystemVersion;// +0x2A
    WORD        MajorImageVersion;          // +0x2C
    WORD        MinorImageVersion;          // +0x2E
    WORD        MajorSubsystemVersion;      // +0x30
    WORD        MinorSubsystemVersion;      // +0x32
    DWORD       Win32VersionValue;          // +0x34
    DWORD       SizeOfImage;                // +0x38
    DWORD       SizeOfHeaders;              // +0x3C
    DWORD       CheckSum;                   // +0x40
    WORD        Subsystem;                  // +0x44
    WORD        DllCharacteristics;         // +0x46
    ULONGLONG   SizeOfStackReserve;         // +0x48  64-bit
    ULONGLONG   SizeOfStackCommit;          // +0x50  64-bit
    ULONGLONG   SizeOfHeapReserve;          // +0x58  64-bit
    ULONGLONG   SizeOfHeapCommit;           // +0x60  64-bit
    DWORD       LoaderFlags;                // +0x68
    DWORD       NumberOfRvaAndSizes;        // +0x6C
    IMAGE_DATA_DIRECTORY DataDirectory[16]; // +0x70  8 bytes each × 16 = 128 bytes
} IMAGE_OPTIONAL_HEADER64;
// Total size: 0x70 + 0x80 = 0xF0 (240 bytes)
```

---

## Key Optional Header Fields: Deep Dive

### `Magic` — PE Format Identifier

**Offset**: +0x00 (from OptionalHeader base) | **Type**: WORD

| Value    | Constant                     | Format |
|----------|------------------------------|--------|
| `0x010B` | IMAGE_NT_OPTIONAL_HDR32_MAGIC| PE32 (32-bit) |
| `0x020B` | IMAGE_NT_OPTIONAL_HDR64_MAGIC| PE32+ (64-bit) |
| `0x0107` | IMAGE_ROM_OPTIONAL_HDR_MAGIC | ROM image (rare, embedded systems) |

This is how shellcode (and the loader) determines whether to interpret the optional header as
PE32 or PE32+. In PE32+, `ImageBase` is at a different offset and is 8 bytes wide.

**Shellcode architecture detection**:
```nasm
; EBX = NT headers base (base + e_lfanew)
; OptionalHeader starts at EBX + 0x18
movzx eax, word [ebx + 0x18]     ; Read Magic field
cmp   eax, 0x020B                 ; PE32+?
je    .handle_64bit
cmp   eax, 0x010B                 ; PE32?
je    .handle_32bit
; Unknown magic — bail
```

---

### `AddressOfEntryPoint` — Program Entry Point RVA

**Offset from OptionalHeader**: +0x10 | **Type**: DWORD | Same in both PE32 and PE32+

This is the RVA of the first instruction that executes when the PE is loaded. It is always a
DWORD (32-bit) even in PE32+ — RVAs are never 64-bit in the PE format.

**What the entry point actually is**: For MSVC-compiled programs, the entry point is NOT `main()`
or `WinMain()`. It is the CRT startup function (`mainCRTStartup`, `WinMainCRTStartup`, or
`_DllMainCRTStartup`). This function initializes the C runtime library (sets up global
constructors, initializes `argc`/`argv`, etc.) before calling the user's `main()`.

**For DLLs**: The entry point is `DllMain`. If the DLL has no DllMain, the linker inserts a
stub that simply returns TRUE.

**ASLR interaction**: The value stored in this field is a fixed RVA — it does not change when
ASLR randomizes the load address. The actual entry point VA at runtime is:
```
entry_point_VA = current_ImageBase + AddressOfEntryPoint
```

**Shellcode use**: Rarely needed for API resolution, but essential when manually mapping and
executing a PE payload. After mapping all sections and applying relocations, transfer execution
to `mapped_base + AddressOfEntryPoint`.

---

### `ImageBase` — Preferred Load Address

**Offset from OptionalHeader**:
- PE32: +0x1C | **Type**: DWORD (32-bit)
- PE32+: +0x18 | **Type**: ULONGLONG (64-bit)

This is the address at which the linker assumed the image would be loaded when it computed all
absolute addresses (before ASLR existed). It is the "preferred" load address.

**Default values by linker**:
- EXE: `0x00400000` (PE32) / `0x0000000140000000` (PE32+)
- DLL: `0x10000000` (PE32) / `0x0000000180000000` (PE32+)
- System DLLs (kernel32, ntdll): assigned specific bases by the OS image layout

**What happens when ASLR changes ImageBase**: The Windows loader:
1. Selects a random base address via `MiSelectAddress` (kernel function)
2. Maps the PE at the new address
3. Applies base relocations (section `.reloc`, DataDirectory[5]) to fix up all absolute references
4. The PE runs correctly at the new address

**Critical for shellcode**: When you resolve a module's base via the PEB (`DllBase`), that IS the
current load address (possibly ASLR-randomized). The `ImageBase` field in the optional header
contains the *preferred* (compile-time) base — often different. Always use the PEB `DllBase` for
RVA-to-VA conversions, not the `ImageBase` field.

---

### `SectionAlignment` and `FileAlignment`

**Offsets**: +0x20 and +0x24 | **Type**: DWORD each | Same in both variants

`SectionAlignment` is the alignment boundary (in bytes) for sections when mapped into memory.
All sections start at a multiple of this value relative to ImageBase. Typical value: `0x1000`
(4KB, one memory page).

`FileAlignment` is the alignment boundary (in bytes) for section data within the PE file on disk.
Typical value: `0x200` (512 bytes, one disk sector) or `0x1000`.

**Why they differ**: On disk, packing section data to 512-byte boundaries conserves file size.
In memory, sections must align to page boundaries (4KB minimum) for the memory manager to apply
per-page protections (read, write, execute). A `.text` section at file offset `0x400` with
`SectionAlignment = 0x1000` will be mapped to `ImageBase + 0x1000` in memory.

**Implication for RVA-to-file-offset conversion**: The mapping is NOT `file_offset = RVA` for
most binaries. A section with file offset `0x400` might map to memory at `ImageBase + 0x1000`.
You must use section headers to convert between RVA and file offset. (In shellcode, you operate
on memory-mapped images, so this conversion is irrelevant — you always work with RVAs and VAs.)

---

### `SizeOfImage` — Total Mapped Size

**Offset from OptionalHeader**: +0x38 | **Type**: DWORD | Same in both variants

The total size in bytes of the PE image when mapped into memory, including all headers and
sections, rounded up to a multiple of `SectionAlignment`. The Windows loader calls
`VirtualAlloc(NULL, SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)` (conceptually)
to reserve the virtual address range before mapping sections.

**Shellcode use**: Required when manually mapping a PE payload in memory (e.g., in reflective DLL
injection). The manual mapper calls VirtualAlloc with this size, then copies headers and sections
to the allocated region.

---

### `DllCharacteristics` — Security and Loading Flags

**Offset from OptionalHeader**: +0x46 | **Type**: WORD | Same in both variants

| Value    | Constant                                   | Meaning                                    |
|----------|--------------------------------------------|--------------------------------------------|
| `0x0020` | IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA   | 64-bit ASLR (high entropy random base)     |
| `0x0040` | IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE      | Opt into ASLR (can be relocated)           |
| `0x0080` | IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY   | Code integrity (signed) required           |
| `0x0100` | IMAGE_DLLCHARACTERISTICS_NX_COMPAT         | DEP/NX compatible (no execute on data)     |
| `0x0200` | IMAGE_DLLCHARACTERISTICS_NO_ISOLATION      | No manifests/isolation                     |
| `0x0400` | IMAGE_DLLCHARACTERISTICS_NO_SEH            | No structured exception handling           |
| `0x0800` | IMAGE_DLLCHARACTERISTICS_NO_BIND           | Do not bind this image                     |
| `0x1000` | IMAGE_DLLCHARACTERISTICS_APPCONTAINER      | Must execute in AppContainer               |
| `0x2000` | IMAGE_DLLCHARACTERISTICS_WDM_DRIVER        | A WDM driver                               |
| `0x4000` | IMAGE_DLLCHARACTERISTICS_GUARD_CF          | Control Flow Guard enabled                 |
| `0x8000` | IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE | Terminal server aware                  |

**Exploit relevance**:
- `DYNAMIC_BASE` (0x0040): if this bit is absent, the loader will NOT apply ASLR to this module —
  it will always load at `ImageBase`. Many older or third-party applications lack this flag,
  enabling reliable ROP gadget addressing without infoleak.
- `NX_COMPAT` (0x0100): if absent, the loader does not enable DEP for this process (on 32-bit
  Windows). This flag must be present for the system's DEP policy to apply DEP to the process.
- `GUARD_CF` (0x4000): Control Flow Guard is active. Indirect calls (including `call [eax]`
  style function pointer calls) are validated against a bitmap. This significantly complicates
  ROP and shellcode that calls through function pointers.
- `NO_SEH` (0x0400): structured exception handlers are not registered. Disables SEH-based
  exploitation techniques (overwriting SEH chain entries).

---

## DataDirectory Array

The DataDirectory is an array of 16 `IMAGE_DATA_DIRECTORY` structures located at the end of the
optional header. Each entry is 8 bytes:

```c
typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD   VirtualAddress;   // +0x00  RVA of the directory
    DWORD   Size;             // +0x04  Size of the directory in bytes
} IMAGE_DATA_DIRECTORY;
```

**Location of DataDirectory**:
- PE32: starts at OptionalHeader base + 0x60 (within NT headers: NT base + 0x18 + 0x60 = NT+0x78)
- PE32+: starts at OptionalHeader base + 0x70 (within NT headers: NT base + 0x18 + 0x70 = NT+0x88)

`VirtualAddress` is an RVA. `Size` is the size of the pointed-to structure, used by the loader
for bounds checking. If `VirtualAddress = 0`, the directory is absent.

### All 16 Data Directory Entries

| Index | Constant                               | Purpose                                     |
|-------|----------------------------------------|---------------------------------------------|
| 0     | IMAGE_DIRECTORY_ENTRY_EXPORT           | Export directory (IMAGE_EXPORT_DIRECTORY)   |
| 1     | IMAGE_DIRECTORY_ENTRY_IMPORT           | Import descriptor table                     |
| 2     | IMAGE_DIRECTORY_ENTRY_RESOURCE         | Resource directory (.rsrc section)          |
| 3     | IMAGE_DIRECTORY_ENTRY_EXCEPTION        | Exception directory (.pdata, unwind info)   |
| 4     | IMAGE_DIRECTORY_ENTRY_SECURITY         | Attribute certificate (Authenticode sig)    |
| 5     | IMAGE_DIRECTORY_ENTRY_BASERELOC        | Base relocation table (.reloc section)      |
| 6     | IMAGE_DIRECTORY_ENTRY_DEBUG            | Debug directory                             |
| 7     | IMAGE_DIRECTORY_ENTRY_ARCHITECTURE     | Architecture-specific data (reserved)      |
| 8     | IMAGE_DIRECTORY_ENTRY_GLOBALPTR        | Global pointer (MIPS/Alpha RVA of gp)      |
| 9     | IMAGE_DIRECTORY_ENTRY_TLS              | Thread Local Storage directory              |
| 10    | IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG      | Load configuration directory                |
| 11    | IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT     | Bound import descriptors                    |
| 12    | IMAGE_DIRECTORY_ENTRY_IAT              | Import Address Table (IAT) RVA              |
| 13    | IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT     | Delay-load import descriptors               |
| 14    | IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR   | COM+ / .NET metadata header                 |
| 15    | (reserved)                             | Zero, reserved for future use               |

### Critical Directories for Exploit Development

**[0] Export Directory — CRITICAL for shellcode**

The RVA and size of IMAGE_EXPORT_DIRECTORY. Every shellcode API resolver reads this entry.

```nasm
; PE32: DataDirectory[0] is at OptionalHeader+0x60, OptionalHeader is at NT+0x18
; So export directory RVA is at: NT_base + 0x18 + 0x60 = NT_base + 0x78
; PE32+: export directory RVA is at: NT_base + 0x18 + 0x70 = NT_base + 0x88
```

For PE32 shellcode targeting 32-bit processes:
```nasm
; EBX = NT headers base
mov eax, [ebx + 0x78]    ; DataDirectory[0].VirtualAddress (export dir RVA)
add eax, ebx             ; Convert to VA: export dir VA = module_base + RVA
; Wait: ebx is NT headers base, not module base.
; Need to add NT headers base's relationship to module base.
; Actually: module_base = [ebx] backward pointer — we need to track module base separately
```

The correct approach keeps module base in a register:
```nasm
; ECX = module base address
; EDX = NT headers base (ECX + e_lfanew)
mov eax, [edx + 0x78]    ; DataDirectory[0].VirtualAddress
add eax, ecx             ; VA = module_base + export_dir_RVA
```

**[1] Import Directory**

The Import Descriptor Table lists all DLLs and functions this module imports. Useful for
identifying what a module depends on; not needed for shellcode API resolution (shellcode resolves
APIs from the export tables of loaded DLLs instead).

**[5] Base Relocation Table — ASLR enabling mechanism**

Contains a list of all absolute addresses in the PE's code and data that need to be patched when
the image loads at a different base than `ImageBase`. Each relocation entry specifies a page RVA
and a list of offsets within that page that hold absolute addresses.

The loader applies relocations as:
```
*address_to_fix += (actual_load_base - preferred_ImageBase)
```

**For exploit development**: If this directory is absent (or the `IMAGE_FILE_RELOCS_STRIPPED`
characteristic is set), the image cannot be relocated — it must load at `ImageBase`. This is
the situation with old EXEs and some compiled-as-fixed DLLs — they are ASLR-immune and always
provide reliable gadget addresses.

**[4] Security Certificate Directory**

Contains the Authenticode digital signature. Notably: this directory's `VirtualAddress` is a
**raw file offset** (not an RVA) — the only exception to the RVA convention in data directories.
The signature is appended to the file and is not mapped into the process image. This means
modifying the PE after signing invalidates the signature but the file still runs (unless code
integrity enforcement is active).

**[9] TLS Directory — Shellcode injection vector**

Thread Local Storage callbacks execute BEFORE the entry point when a module is loaded (including
during `LoadLibrary`). TLS callbacks receive a `DLL_PROCESS_ATTACH` notification and can run
arbitrary code.

**Exploit relevance**: TLS callbacks are a reliable anti-debugging and code execution mechanism.
A PE loaded via `LoadLibrary` will execute TLS callbacks before DllMain. Many sandbox systems
do not monitor TLS callback execution separately from entry point execution, making TLS a
persistent shellcode injection vector in crafted DLLs.

The TLS directory entry points to an `IMAGE_TLS_DIRECTORY` structure whose `AddressOfCallBacks`
field is an absolute VA (not RVA) pointing to an array of TLS callback function pointers.

---

## x86 vs x64 Differences

### Offset Comparison Table

The following table shows every OptionalHeader field with its offset in both PE32 and PE32+.
Fields where the offset changes are marked with *.

| Field                      | PE32 (x86) | PE32+ (x64) | Size (PE32) | Size (PE32+) |
|----------------------------|------------|-------------|-------------|--------------|
| `Magic`                    | +0x00      | +0x00       | WORD        | WORD         |
| `MajorLinkerVersion`       | +0x02      | +0x02       | BYTE        | BYTE         |
| `MinorLinkerVersion`       | +0x03      | +0x03       | BYTE        | BYTE         |
| `SizeOfCode`               | +0x04      | +0x04       | DWORD       | DWORD        |
| `SizeOfInitializedData`    | +0x08      | +0x08       | DWORD       | DWORD        |
| `SizeOfUninitializedData`  | +0x0C      | +0x0C       | DWORD       | DWORD        |
| `AddressOfEntryPoint`      | +0x10      | +0x10       | DWORD       | DWORD        |
| `BaseOfCode`               | +0x14      | +0x14       | DWORD       | DWORD        |
| `BaseOfData`               | +0x18      | **absent**  | DWORD       | —            |
| `ImageBase`                | +0x1C      | *+0x18      | DWORD       | ULONGLONG    |
| `SectionAlignment`         | +0x20      | *+0x20      | DWORD       | DWORD        |
| `FileAlignment`            | +0x24      | *+0x24      | DWORD       | DWORD        |
| `MajorOSVersion`           | +0x28      | *+0x28      | WORD        | WORD         |
| `MinorOSVersion`           | +0x2A      | *+0x2A      | WORD        | WORD         |
| `MajorImageVersion`        | +0x2C      | *+0x2C      | WORD        | WORD         |
| `MinorImageVersion`        | +0x2E      | *+0x2E      | WORD        | WORD         |
| `MajorSubsystemVersion`    | +0x30      | *+0x30      | WORD        | WORD         |
| `MinorSubsystemVersion`    | +0x32      | *+0x32      | WORD        | WORD         |
| `Win32VersionValue`        | +0x34      | *+0x34      | DWORD       | DWORD        |
| `SizeOfImage`              | +0x38      | *+0x38      | DWORD       | DWORD        |
| `SizeOfHeaders`            | +0x3C      | *+0x3C      | DWORD       | DWORD        |
| `CheckSum`                 | +0x40      | *+0x40      | DWORD       | DWORD        |
| `Subsystem`                | +0x44      | *+0x44      | WORD        | WORD         |
| `DllCharacteristics`       | +0x46      | *+0x46      | WORD        | WORD         |
| `SizeOfStackReserve`       | +0x48      | *+0x48      | DWORD       | ULONGLONG    |
| `SizeOfStackCommit`        | +0x4C      | *+0x50      | DWORD       | ULONGLONG    |
| `SizeOfHeapReserve`        | +0x50      | *+0x58      | DWORD       | ULONGLONG    |
| `SizeOfHeapCommit`         | +0x54      | *+0x60      | DWORD       | ULONGLONG    |
| `LoaderFlags`              | +0x58      | *+0x68      | DWORD       | DWORD        |
| `NumberOfRvaAndSizes`      | +0x5C      | *+0x6C      | DWORD       | DWORD        |
| `DataDirectory[0]`         | +0x60      | *+0x70      | 8 bytes     | 8 bytes      |
| `DataDirectory[1]`         | +0x68      | *+0x78      | 8 bytes     | 8 bytes      |

**Key takeaway**: `ImageBase` is at +0x1C in PE32 but at +0x18 in PE32+ (due to `BaseOfData`
being removed). `DataDirectory[0].VirtualAddress` (export directory RVA) is at:
- PE32: OptionalHeader + 0x60 = NT headers + 0x78
- PE32+: OptionalHeader + 0x70 = NT headers + 0x88

This offset difference is critical for shellcode that must work on both architectures.

### Architecture-Adaptive Shellcode Pattern

```nasm
;------------------------------------------------------------------
; get_export_dir_rva
; Works for both PE32 and PE32+
; Input:  ECX = module base
;         EDX = NT headers base (ECX + e_lfanew)
; Output: EAX = export directory RVA (0 if none)
;------------------------------------------------------------------
get_export_dir_rva:
    movzx eax, word [edx + 0x18]   ; OptionalHeader.Magic
    cmp   eax, 0x020B              ; PE32+?
    je    .pe32plus
    ; PE32: DataDirectory[0].VirtualAddress at NT+0x78
    mov   eax, [edx + 0x78]
    ret
.pe32plus:
    ; PE32+: DataDirectory[0].VirtualAddress at NT+0x88
    mov   eax, [edx + 0x88]
    ret
```

---

## Assembly Traversal

### Complete Path: Module Base → Export Directory RVA

```nasm
;------------------------------------------------------------------
; Full PE32 traversal from module base to export directory VA
; Input:  EBX = module base (e.g., kernel32.dll base from PEB)
; Output: ESI = export directory VA
; Clobbers: EAX, ECX
;------------------------------------------------------------------

pe32_to_export_dir:
    ; Step 1: Validate DOS header magic
    cmp word [ebx], 0x5A4D
    jne .error

    ; Step 2: Read e_lfanew (offset to NT headers)
    mov eax, [ebx + 0x3C]        ; e_lfanew
    add eax, ebx                  ; EAX = VA of IMAGE_NT_HEADERS

    ; Step 3: Validate PE signature
    cmp dword [eax], 0x00004550   ; "PE\0\0"
    jne .error

    ; Step 4: Validate PE32 magic (not PE32+)
    ; OptionalHeader is at NT+0x18; Magic is at OptionalHeader+0x00
    cmp word [eax + 0x18], 0x010B ; IMAGE_NT_OPTIONAL_HDR32_MAGIC
    jne .error

    ; Step 5: Get export directory RVA from DataDirectory[0]
    ; DataDirectory[0].VirtualAddress is at OptionalHeader+0x60 = NT+0x78
    mov ecx, [eax + 0x78]         ; export dir RVA
    test ecx, ecx
    jz  .no_exports               ; no export directory

    ; Step 6: Convert export dir RVA to VA
    lea esi, [ebx + ecx]          ; ESI = module_base + export_dir_RVA
                                   ;     = VA of IMAGE_EXPORT_DIRECTORY
    ret

.no_exports:
    xor esi, esi
    ret

.error:
    xor esi, esi
    ret
```

---

## WinDbg Verification

### Using `!dh` to Display All NT Header Fields

```
0:000> !dh kernel32

File Type: DLL
FILE HEADER VALUES
     14C machine (i386)
       4 number of sections
5A5B1A1C time date stamp Mon Jan 15 06:44:12 2018

       0 file pointer to symbol table
       0 number of symbols
      E0 size of optional header
    2102 characteristics
            Executable
            32 bit word machine
            DLL

OPTIONAL HEADER VALUES
     10B magic #
    ...
    8003 base of code
   10000 base of data
76B40000 image base
    1000 section alignment
     200 file alignment
   ...
   F8DD checksum
       2 subsystem (Windows GUI)
     ...
76B40000 image base
    ...
       0 [       0] address [size] of Export Directory
       0 [       0] address [size] of Import Directory
```

Note: `!dh` shows DataDirectory entries as `address [size]` pairs where address is the RVA.

### Using `dt` to Walk the Structure

```
0:000> dt ntdll!_IMAGE_NT_HEADERS kernel32
ntdll!_IMAGE_NT_HEADERS
   +0x000 Signature        : 0x4550
   +0x004 FileHeader       : _IMAGE_FILE_HEADER
   +0x018 OptionalHeader   : _IMAGE_OPTIONAL_HEADER
```

```
0:000> dt ntdll!_IMAGE_FILE_HEADER kernel32+4
ntdll!_IMAGE_FILE_HEADER
   +0x000 Machine              : 0x14c
   +0x002 NumberOfSections     : 4
   +0x004 TimeDateStamp        : 0x5a5b1a1c
   +0x008 PointerToSymbolTable : 0
   +0x00c NumberOfSymbols      : 0
   +0x010 SizeOfOptionalHeader : 0xe0
   +0x012 Characteristics      : 0x2102
```

### DataDirectory Access

Get the export directory RVA from NT headers at offset 0x78 (PE32):
```
0:000> dd kernel32+e_lfanew_value+78 L 2
76b400c8  00000000 00000000
```

(This shows RVA=0 and Size=0 — kernel32 in this example has no exports at this offset;
use `!dh kernel32` to get the correct RVA from the formatted output.)

For a DLL with exports (e.g., ntdll.dll):
```
0:000> !dh ntdll
...
  26740 [    96D4] address [size] of Export Directory
...
```

Then:
```
0:000> dt ntdll!_IMAGE_EXPORT_DIRECTORY ntdll+26740
```

---

## Common Mistakes

### Mistake 1: Using the Wrong DataDirectory Offset for PE32 vs PE32+

The export directory RVA is at different offsets depending on whether the target is PE32 or PE32+:
- PE32: NT headers base + 0x78
- PE32+: NT headers base + 0x88

Shellcode that hardcodes `[NT_base + 0x78]` will read the wrong field when targeting a 64-bit
process. Always check the `Magic` field at NT+0x18 first.

### Mistake 2: Using `ImageBase` from the Header Instead of PEB DllBase

The `ImageBase` field in the optional header contains the linker's **preferred** load address.
Due to ASLR, the actual runtime load address (stored as `DllBase` in the LDR_DATA_TABLE_ENTRY)
will almost certainly differ.

```c
// WRONG: reading ImageBase from header
DWORD* pOptHdr = (DWORD*)((BYTE*)base + e_lfanew + 0x18);
DWORD imageBase = pOptHdr[7]; // +0x1C in PE32 optional header

// RIGHT: using the address you already have
PVOID imageBase = module_base; // the address from the PEB, which IS the loaded base
```

All RVA-to-VA conversions must use the runtime module base, not the header's `ImageBase`.

### Mistake 3: Not Checking `NumberOfRvaAndSizes` Before Accessing DataDirectory

The `NumberOfRvaAndSizes` field at OptionalHeader+0x5C (PE32) specifies how many DataDirectory
entries are actually present. While the PE spec defines 16 entries, a PE file could specify
fewer (as low as 0). Accessing `DataDirectory[9]` (TLS) on a PE with `NumberOfRvaAndSizes = 5`
would read out-of-bounds.

```nasm
; Safe access of DataDirectory[0]:
mov eax, [edx + 0x5C + 0x18]   ; NumberOfRvaAndSizes (at NT+0x74 for PE32)
test eax, eax
jz  .no_data_directories
; DataDirectory[0] index = 0, so we need at least 1 entry
cmp eax, 1
jb  .no_export_dir
; safe to read DataDirectory[0] now
```

In practice, shellcode targeting system DLLs can skip this check since Windows system DLLs
always have a full set of 16 directory entries. Include it in production-quality shellcode.

### Mistake 4: Treating `SizeOfImage` as the File Size

`SizeOfImage` is the size of the in-memory image, not the file on disk. It can be significantly
larger than the file size because:
- `SectionAlignment` pads sections to page boundaries (4KB minimum)
- Uninitialized data sections (`.bss`) have size in memory but zero size on disk

Do not use `SizeOfImage` to allocate a buffer for reading the PE file from disk. Use the actual
file size obtained from the filesystem API.

### Mistake 5: Forgetting That `AddressOfEntryPoint` Is an RVA

```c
// WRONG:
FARPROC entryPoint = (FARPROC)pOptHdr->AddressOfEntryPoint;
entryPoint();  // crashes — 0x1000 is not a valid address

// RIGHT:
FARPROC entryPoint = (FARPROC)(module_base + pOptHdr->AddressOfEntryPoint);
entryPoint();
```

---

## Exploit and Shellcode Relevance

### Summary: What Shellcode Reads from NT Headers

| Goal                               | Location                        | Field                    |
|------------------------------------|----------------------------------|--------------------------|
| Confirm PE file                    | NT base + 0x00                  | Signature (0x00004550)   |
| Determine 32 vs 64-bit             | NT base + 0x18                  | OptionalHeader.Magic     |
| Find export directory              | NT base + 0x78 (PE32)           | DataDirectory[0].VirtualAddress |
| Find import directory              | NT base + 0x80 (PE32)           | DataDirectory[1].VirtualAddress |
| Find TLS callbacks                 | NT base + 0xA8 (PE32)           | DataDirectory[9].VirtualAddress |
| Get entry point                    | NT base + 0x28 (PE32)           | OptionalHeader.AddressOfEntryPoint |
| Check ASLR/DEP flags               | NT base + 0x5E (PE32)           | OptionalHeader.DllCharacteristics |
| Check if DLL                       | NT base + 0x16                  | FileHeader.Characteristics |
| Locate section table               | NT base + 0x18 + SizeOfOptHdr   | (computed)               |

### The Critical x86 Shellcode Path (PE32 only, fixed offsets)

Most classic Windows shellcode targets 32-bit processes and uses these fixed PE32 offsets:

```nasm
; EBX = module base
mov eax, [ebx + 0x3C]      ; e_lfanew
add eax, ebx                ; EAX = NT headers

; EAX = NT headers base
; +0x00 = Signature (must be 0x00004550)
; +0x18 = OptionalHeader.Magic (must be 0x010B for PE32)
; +0x78 = DataDirectory[0].VirtualAddress (export dir RVA)
```

This three-step sequence — `[base+0x3C]` → add base → `[NT+0x78]` — is the backbone of every
hash-based API resolver in x86 Windows shellcode, including the classic Metasploit
`block_api` stub and its descendants.
