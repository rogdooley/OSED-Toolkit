# IMAGE_DOS_HEADER — MZ Header Reference for Exploit Development

## Table of Contents

1. [Purpose and Historical Context](#purpose-and-historical-context)
2. [Structure Overview](#structure-overview)
3. [Full Field Table](#full-field-table)
4. [Deep Field Explanations](#deep-field-explanations)
5. [The DOS Stub](#the-dos-stub)
6. [Assembly Traversal](#assembly-traversal)
7. [x86 vs x64 Differences](#x86-vs-x64-differences)
8. [WinDbg Verification](#windbg-verification)
9. [Common Mistakes](#common-mistakes)
10. [Exploit and Shellcode Relevance](#exploit-and-shellcode-relevance)

---

## Purpose and Historical Context

### Why the DOS Header Still Exists

The IMAGE_DOS_HEADER is a 64-byte structure that begins every valid PE (Portable Executable) file on
Windows. It was inherited from the MS-DOS executable format (`.EXE` files) introduced in DOS 2.0 around
1983. The format predates Windows by nearly a decade.

When Microsoft designed the Win32 PE format in the early 1990s (formalized for Windows NT 3.1 in 1993),
they faced a compatibility problem: millions of DOS executables existed, and the Windows loader needed to
distinguish DOS binaries from PE binaries. Rather than invent a new signature that would require every
DOS loader to be updated, Microsoft embedded the PE structure after the DOS header, using the DOS
header's `e_lfanew` field as a forward pointer to the actual PE content.

**The result**: every `.EXE` and `.DLL` file on Windows today opens with a DOS header whose only job
in modern use is to point to the real PE header via `e_lfanew`. The rest of the DOS header fields are
vestigial and largely ignored by the Windows PE loader (though the loader does validate the `e_magic`
field).

### The Linker's Role

Modern compilers (MSVC, GCC/MinGW, LLVM/Clang targeting Windows) all emit the DOS header
automatically during the link phase. The linker:

1. Writes the fixed 64-byte DOS header with `e_magic = 0x5A4D` ("MZ")
2. Writes a short DOS stub program (typically 64–128 bytes) that prints "This program cannot be run
   in DOS mode" and exits
3. Aligns to a paragraph boundary (multiples of 16 bytes)
4. Writes the PE signature and remainder of the PE structure
5. Stores the file offset of step 4 in `e_lfanew`

The "MZ" signature comes from Mark Zbikowski, one of the DOS architects at Microsoft. This is his
initials embedded in every executable file on Windows.

### Exploit Relevance at a Glance

The DOS header is the mandatory entry point for all PE parsing in shellcode. To find any other PE
structure — NT headers, sections, exports, imports — you must first locate the DOS header (the module
base address) and extract `e_lfanew`. There is no other path. Understanding this structure is
prerequisite to all PE-walking shellcode techniques.

---

## Structure Overview

```
typedef struct _IMAGE_DOS_HEADER {
    WORD   e_magic;       // +0x00  Magic number ("MZ")
    WORD   e_cblp;        // +0x02  Bytes on last page of file
    WORD   e_cp;          // +0x04  Pages in file
    WORD   e_crlc;        // +0x06  Relocations
    WORD   e_cparhdr;     // +0x08  Size of header in paragraphs
    WORD   e_minalloc;    // +0x0A  Minimum extra paragraphs needed
    WORD   e_maxalloc;    // +0x0C  Maximum extra paragraphs needed
    WORD   e_ss;          // +0x0E  Initial (relative) SS value
    WORD   e_sp;          // +0x10  Initial SP value
    WORD   e_csum;        // +0x12  Checksum
    WORD   e_ip;          // +0x14  Initial IP value
    WORD   e_cs;          // +0x16  Initial (relative) CS value
    WORD   e_lfarlc;      // +0x18  File address of relocation table
    WORD   e_ovno;        // +0x1A  Overlay number
    WORD   e_res[4];      // +0x1C  Reserved words (8 bytes)
    WORD   e_oemid;       // +0x24  OEM identifier
    WORD   e_oeminfo;     // +0x26  OEM information
    WORD   e_res2[10];    // +0x28  Reserved words (20 bytes)
    LONG   e_lfanew;      // +0x3C  File address of new exe header (RVA to PE)
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
```

Total size: 64 bytes (0x40 bytes). The structure ends at offset 0x3F; `e_lfanew` occupies offsets
0x3C–0x3F.

---

## Full Field Table

| Field         | Offset | Size   | Type  | Purpose                                                  |
|---------------|--------|--------|-------|----------------------------------------------------------|
| `e_magic`     | +0x00  | 2 bytes| WORD  | Magic number: must be 0x5A4D ("MZ") for DOS/PE files    |
| `e_cblp`      | +0x02  | 2 bytes| WORD  | Bytes on the last page of the DOS file (0 = full page)  |
| `e_cp`        | +0x04  | 2 bytes| WORD  | Number of 512-byte pages in the DOS file                 |
| `e_crlc`      | +0x06  | 2 bytes| WORD  | Number of relocation entries in the DOS relocation table |
| `e_cparhdr`   | +0x08  | 2 bytes| WORD  | Size of the DOS header in 16-byte paragraphs            |
| `e_minalloc`  | +0x0A  | 2 bytes| WORD  | Minimum additional paragraphs of memory required        |
| `e_maxalloc`  | +0x0C  | 2 bytes| WORD  | Maximum additional paragraphs of memory requested       |
| `e_ss`        | +0x0E  | 2 bytes| WORD  | Initial SS register value (relative segment for stack)  |
| `e_sp`        | +0x10  | 2 bytes| WORD  | Initial SP register value                               |
| `e_csum`      | +0x12  | 2 bytes| WORD  | Checksum of the DOS file (rarely validated)             |
| `e_ip`        | +0x14  | 2 bytes| WORD  | Initial IP register value (DOS entry point)             |
| `e_cs`        | +0x16  | 2 bytes| WORD  | Initial CS register value (relative code segment)       |
| `e_lfarlc`    | +0x18  | 2 bytes| WORD  | File offset of the DOS relocation table                 |
| `e_ovno`      | +0x1A  | 2 bytes| WORD  | Overlay number (0 = main program, not an overlay)       |
| `e_res[4]`    | +0x1C  | 8 bytes| WORD[]| Reserved, must be zero                                  |
| `e_oemid`     | +0x24  | 2 bytes| WORD  | OEM identifier (for e_oeminfo)                          |
| `e_oeminfo`   | +0x26  | 2 bytes| WORD  | OEM information specific to e_oemid                     |
| `e_res2[10]`  | +0x28  | 20 bytes|WORD[]| Reserved, must be zero                                  |
| `e_lfanew`    | +0x3C  | 4 bytes| LONG  | File offset (RVA) of the IMAGE_NT_HEADERS structure     |

**Field count**: 19 distinct named fields (some are arrays), totaling 29 WORD-sized slots plus
one LONG.

---

## Deep Field Explanations

### `e_magic` — Offset 0x00, WORD (2 bytes)

This is the signature that identifies a valid DOS or PE executable. The value must be `0x5A4D`.

**Byte layout in memory** (little-endian):
```
Offset 0x00: 0x4D  ('M')
Offset 0x01: 0x5A  ('Z')
```

Reading the bytes sequentially as ASCII gives "MZ". Reading as a 16-bit little-endian WORD gives
`0x5A4D`. Both representations are correct — the confusion lies in which direction you read.

**Who sets this field**: The linker always sets this. It cannot be set by the compiler — only the
linker, which assembles the final binary, writes the DOS header.

**How to verify in code**:
```c
PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)module_base;
if (pDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {  // IMAGE_DOS_SIGNATURE = 0x5A4D
    // Not a valid PE
}
```

**Windows PE loader behavior**: The loader reads the first two bytes of the file (or mapped image).
If they do not equal `0x5A4D`, the loader immediately rejects the file with `STATUS_INVALID_IMAGE_FORMAT`.
This check happens before any other PE validation.

**Shellcode consideration**: When walking the PEB's loaded module list, each entry's `DllBase` points
to a mapped PE image in memory. You should validate `e_magic` before dereferencing `e_lfanew` to
avoid crashing on non-PE memory regions.

---

### `e_lfanew` — Offset 0x3C, LONG (4 bytes) — THE CRITICAL FIELD

This 32-bit signed integer holds the **file offset** (equivalently: the RVA from the start of the
loaded image) to the IMAGE_NT_HEADERS structure. It is the single most important field in the DOS
header for all PE parsing, including shellcode.

**Why it is at offset 0x3C specifically**:

The offset 0x3C was chosen by the designers of the Windows NT PE format because:
- Offsets 0x00–0x1B are the original DOS header fields needed for actual DOS program loading
- Offsets 0x1C–0x3B are reserved/OEM fields that DOS ignores
- Offset 0x3C is the last 4 bytes of the 64-byte DOS header (0x40 = 64 bytes total; 0x3C + 4 = 0x40)
- Placing it at the very end of the DOS header meant it would not conflict with any existing DOS
  header consumer while remaining easy to locate (always at a fixed offset from the base)

There is no formal document explaining why 0x3C was chosen over 0x38 or another offset. The
placement at the tail of the structure (last 4 bytes of the 64-byte header) is logical: any DOS
loader reading sequentially stops before this field, while PE-aware code knows exactly where to look.

**Value interpretation**:

The value stored in `e_lfanew` is a **file offset** — the number of bytes from the beginning of the
file to the start of IMAGE_NT_HEADERS. In a loaded (memory-mapped) PE image, because the DOS header
is mapped starting at offset 0 of the image, the file offset equals the **Relative Virtual Address
(RVA)** from the module's load base.

Therefore, to get the Virtual Address of IMAGE_NT_HEADERS:
```
VA(IMAGE_NT_HEADERS) = ImageBase + e_lfanew
```

**Typical values by compiler/linker**:

| Linker / Tool             | Typical `e_lfanew` |
|---------------------------|--------------------|
| MSVC (Visual Studio)      | 0x00000080         |
| MSVC (older, pre-VS2015)  | 0x00000040         |
| MinGW-w64 / GCC           | 0x00000080         |
| NASM-assembled manual PE  | 0x00000040         |
| Some packers / protectors | 0x00000100+        |
| Malware with hidden data  | Variable / large   |

**Critically**: `e_lfanew` is NOT always 0x40 or 0x80. Shellcode must always read the value
dynamically and not assume a fixed offset.

**What happens if `e_lfanew` is corrupted**:

If `e_lfanew` contains a value that:
- Points past the end of the file → `LoadLibrary` returns error `ERROR_BAD_EXE_FORMAT`
- Points to memory without "PE\0\0" signature → loader rejects with `STATUS_INVALID_IMAGE_FORMAT`
- Is zero → PE loader reads the DOS header as NT headers, immediately fails magic check
- Is negative (as a signed 32-bit value) → interpreted as a large positive RVA; loader rejects

**Shellcode validation pattern**:
```asm
; Assume EBX = module base (loaded image address)
mov eax, [ebx + 0x3C]         ; Read e_lfanew
test eax, eax                  ; Sanity: not zero
jz  .bad_module
cmp eax, 0x1000                ; Sanity: not unreasonably large
jg  .bad_module
; For paranoid shellcode:
add eax, ebx                   ; VA of IMAGE_NT_HEADERS
cmp dword [eax], 0x00004550    ; Verify "PE\0\0" signature
jne .bad_module
```

---

### Remaining Fields: DOS-Era Metadata

The fields `e_cblp`, `e_cp`, `e_crlc`, `e_cparhdr`, `e_minalloc`, `e_maxalloc`, `e_ss`, `e_sp`,
`e_csum`, `e_ip`, `e_cs`, and `e_lfarlc` are all part of the original DOS `.EXE` header format
(EXEPACK format). They describe the DOS program's memory layout and are used by the MS-DOS
program loader (INT 21h, AH=4Bh). They are entirely irrelevant to Windows PE loading and to
shellcode. The Windows PE loader ignores all of them.

`e_oemid` and `e_oeminfo` were intended for OEM-specific extensions. In practice both are always 0
in shipping Windows binaries.

`e_res` and `e_res2` are reserved arrays, always zeroed in production builds. Malware occasionally
uses these zero-padded regions to store small amounts of data.

---

## The DOS Stub

### What the Stub Is

Immediately following the 64-byte DOS header (starting at offset 0x40 in most MSVC-linked binaries)
is the **DOS stub** — a small, valid MS-DOS COM-style program. This program is executed when someone
attempts to run a PE binary directly under MS-DOS or the 16-bit Windows command interpreter.

### What the Stub Does

A typical MSVC-generated DOS stub is approximately 64–128 bytes and does exactly one thing:

1. Sets up a minimal 16-bit environment
2. Calls DOS interrupt INT 21h with AH=09h (print string function)
3. Points DS:DX to the string "This program cannot be run in DOS mode.\r\n$"
4. After printing, calls INT 21h with AH=4Ch, AL=01 (exit with code 1)

The string "This program cannot be run in DOS mode" is visible in virtually every PE binary if you
open it in a hex editor. Its presence at a predictable offset is a secondary signature used by
some security tools to identify PE files.

### Why This String Exists

Microsoft chose this message because:
- It provides a user-friendly explanation when a Windows EXE is accidentally run under DOS
- It requires zero modification to the DOS loader (any valid COM-format stub works)
- It has been standard since Windows NT 3.1 and is reproduced by all major Windows linkers

### Stub Region as a Hiding Spot

Because the stub region (between the end of the DOS header at 0x40 and the start of IMAGE_NT_HEADERS
at `e_lfanew`) is completely ignored by the Windows PE loader, it can contain arbitrary data without
affecting executable behavior.

**Malware abuse techniques**:

1. **Configuration data hiding**: The stub region is large enough (often 32–192 bytes) to store
   small configuration blobs, C2 IP addresses, XOR keys, or secondary payloads. The PE loader
   ignores this data entirely; it is not mapped into a named section and is not checked by most
   AV/EDR scanners that focus on PE sections.

2. **Obfuscated imports**: A loader stub that parses a custom import table hidden in this region,
   used before PE execution begins.

3. **Custom MZ stubs**: Packers frequently replace the standard stub with a custom decompression
   stub that, when run under DOS, decompresses the payload. This also helps defeat signature-based
   detection of the main code.

4. **Increasing `e_lfanew` to create space**: A packer can set `e_lfanew` to 0x200 or larger,
   creating a 512-byte region between the DOS header and NT headers. The Windows loader does not
   care how large this gap is. Shellcode in the gap is invisible to section-walking analysis.

**Detection approach**: Compare `e_lfanew` to expected linker defaults. An unusually large value
(e.g., > 0x100) with non-zero content in the gap region is suspicious and warrants further
inspection.

---

## Assembly Traversal

### Finding IMAGE_NT_HEADERS from Module Base

The following NASM (x86, 32-bit) snippet demonstrates the canonical traversal from a module's
base address to IMAGE_NT_HEADERS. Assume `EBX` contains the module base address (the start of the
loaded image — the address of the DOS header).

```nasm
;------------------------------------------------------------------
; find_nt_headers
; Input:  EBX = module base (address of IMAGE_DOS_HEADER)
; Output: EAX = VA of IMAGE_NT_HEADERS
; Clobbers: EAX
;------------------------------------------------------------------

find_nt_headers:
    ; Step 1: Read e_lfanew
    ; The field e_lfanew is at a fixed offset of 0x3C from the start
    ; of IMAGE_DOS_HEADER (which is the module base). It is a 32-bit
    ; value containing the FILE OFFSET (= in-memory RVA) of
    ; IMAGE_NT_HEADERS.
    mov eax, [ebx + 0x3C]
    ;   EBX = 0x76B40000 (example: kernel32.dll base)
    ;   [EBX + 0x3C] = 0x00000080 (typical MSVC e_lfanew)
    ;   EAX = 0x00000080 after this instruction

    ; Step 2: Convert RVA to VA
    ; e_lfanew is an offset FROM the module base, not an absolute
    ; address. To get the actual memory address (VA) we must ADD
    ; the module base to the RVA.
    ; This is the RVA-to-VA conversion: VA = base + RVA
    add eax, ebx
    ;   EAX = 0x00000080 + 0x76B40000 = 0x76B40080
    ;   EAX now points to the IMAGE_NT_HEADERS structure in memory

    ; Step 3 (optional but recommended): Verify PE signature
    ; IMAGE_NT_HEADERS starts with a 4-byte signature: "PE\0\0"
    ; In little-endian DWORD form this is 0x00004550.
    cmp dword [eax], 0x00004550
    jne .invalid_pe            ; bail out if signature mismatch

    ; EAX is now a valid pointer to IMAGE_NT_HEADERS
    ret

.invalid_pe:
    xor eax, eax               ; return NULL on failure
    ret
```

**Line-by-line explanation**:

- `mov eax, [ebx + 0x3C]` — Indirect memory read. EBX holds the module base. Adding 0x3C gives
  the address of the `e_lfanew` field. The brackets `[...]` dereference it, loading the 4-byte
  value stored there into EAX. EAX now contains the RVA.

- `add eax, ebx` — This is the RVA-to-VA conversion. The RVA stored in `e_lfanew` is a byte
  offset from the module's load address. Adding the module base turns it into a real virtual
  address that can be dereferenced. Without this ADD, EAX would contain an offset (e.g., 0x80)
  which is not a valid pointer to NT headers in the process address space.

- `cmp dword [eax], 0x00004550` — Reads the first 4 bytes at the computed address and compares
  them to the PE signature. This prevents a corrupted or wrong `e_lfanew` from causing a crash
  or misparse when the caller starts reading NT header fields.

### Full Context: Module Walking Prelude

In most shellcode, the module base is found by walking the PEB:

```nasm
;------------------------------------------------------------------
; get_kernel32_base
; Uses PEB → Ldr → InMemoryOrderModuleList to find kernel32.dll base
; Output: EBX = kernel32.dll base address
;------------------------------------------------------------------
get_kernel32_base:
    ; Get PEB from FS:[0x30]
    mov eax, [fs:0x30]          ; EAX = PEB address

    ; Get PEB_LDR_DATA from PEB + 0x0C
    mov eax, [eax + 0x0C]       ; EAX = PEB.Ldr (PEB_LDR_DATA*)

    ; Get first entry of InMemoryOrderModuleList
    ; InMemoryOrderModuleList is at PEB_LDR_DATA + 0x14
    mov eax, [eax + 0x14]       ; EAX = first LIST_ENTRY (Flink)

    ; First entry = ntdll.dll (always), advance to second
    mov eax, [eax]              ; EAX = second LIST_ENTRY

    ; Third entry is typically kernel32.dll
    mov eax, [eax]              ; EAX = third LIST_ENTRY

    ; DllBase is at LDR_DATA_TABLE_ENTRY + 0x10 from InMemoryOrderLinks
    ; (InMemoryOrderLinks is at offset 0x08 in LDR_DATA_TABLE_ENTRY,
    ;  so DllBase is at InMemoryOrderLinks + 0x08 = offset 0x10 from entry)
    mov ebx, [eax + 0x10]       ; EBX = kernel32.dll base address

    ; Now use find_nt_headers from above
    call find_nt_headers        ; EAX = VA of IMAGE_NT_HEADERS
    ret
```

---

## x86 vs x64 Differences

**IMAGE_DOS_HEADER is identical in PE32 (x86) and PE32+ (x64).**

The DOS header structure has not changed between 32-bit and 64-bit PE files. It is always exactly
64 bytes. `e_lfanew` is always a 32-bit field at offset 0x3C. The value it contains is always a
32-bit RVA.

This uniformity makes the DOS header the one PE structure that shellcode can parse identically on
both architectures. The 32-bit/64-bit branching only becomes necessary once you advance past
`e_lfanew` to IMAGE_NT_HEADERS.

**The only practical difference**: in 64-bit processes, the module base addresses held in EBX (or
RBX in x64 shellcode) are 64-bit values, but the ADD operation `add rax, rbx` works identically —
you are still adding a 32-bit RVA to a 64-bit base and getting a 64-bit VA.

```nasm
; x64 equivalent of the DOS header traversal:
; Assume RBX = module base (64-bit)
mov eax, [rbx + 0x3C]     ; e_lfanew is still DWORD (32-bit)
                            ; NASM zero-extends into RAX automatically
                            ; via the 32-bit destination register form
add rax, rbx               ; RAX = 64-bit VA of IMAGE_NT_HEADERS
```

Note: Using `mov eax, ...` (32-bit destination) in x64 mode automatically zero-extends to RAX,
so the ADD with RBX (64-bit) produces a correct 64-bit result.

---

## WinDbg Verification

### Displaying the Full DOS Header

```
0:000> db kernel32 L 0x40
```

This command dumps 0x40 (64) bytes of raw data starting at the kernel32.dll base address, which
is exactly the IMAGE_DOS_HEADER.

**Example output** (addresses will vary due to ASLR):

```
76b40000  4d 5a 90 00 03 00 00 00-04 00 00 00 ff ff 00 00  MZ..............
76b40010  b8 00 00 00 00 00 00 00-40 00 00 00 00 00 00 00  ........@.......
76b40020  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
76b40030  00 00 00 00 00 00 00 00-00 00 00 00 f0 00 00 00  ................
```

**Annotated field mapping**:

```
Offset  Bytes            Field        Value    Notes
+0x00   4D 5A            e_magic      0x5A4D   "MZ" — valid PE signature
+0x02   90 00            e_cblp       0x0090   144 bytes on last page
+0x04   03 00            e_cp         0x0003   3 pages in DOS file
+0x06   00 00            e_crlc       0x0000   no DOS relocations
+0x08   04 00            e_cparhdr    0x0004   4 paragraphs header
+0x0A   00 00            e_minalloc   0x0000
+0x0C   FF FF            e_maxalloc   0xFFFF   request all available memory
+0x0E   00 00            e_ss         0x0000
+0x10   B8 00            e_sp         0x00B8
+0x12   00 00            e_csum       0x0000   no checksum
+0x14   00 00            e_ip         0x0000
+0x16   00 00            e_cs         0x0000
+0x18   40 00            e_lfarlc     0x0040   reloc table at offset 0x40
+0x1A   00 00            e_ovno       0x0000
+0x1C   00 00 00 00      e_res[0..1]  0        reserved, zero
+0x20   00 00 00 00      e_res[2..3]  0        reserved, zero
+0x24   00 00            e_oemid      0x0000
+0x26   00 00            e_oeminfo    0x0000
+0x28   00 00 ... (20)   e_res2[0..9] 0        reserved, zero
+0x3C   F0 00 00 00      e_lfanew     0x000000F0  IMAGE_NT_HEADERS at base+0xF0
```

**Little-endian note**: The bytes `F0 00 00 00` at offset 0x3C are read right-to-left for the
DWORD value: the least-significant byte is first. So `F0 00 00 00` = 0x000000F0, meaning
IMAGE_NT_HEADERS is at `kernel32_base + 0xF0`.

### Verifying e_lfanew Points to "PE\0\0"

```
0:000> dd kernel32+f0 L 1
76b400f0  00004550
```

The value `0x00004550` is the PE signature. In ASCII: 0x50='P', 0x45='E', 0x00='\0', 0x00='\0'.
This confirms `e_lfanew = 0xF0` is correct for this kernel32 build.

### Using dt to Display the Structure

```
0:000> dt _IMAGE_DOS_HEADER kernel32
ntdll!_IMAGE_DOS_HEADER
   +0x000 e_magic          : 0x5a4d
   +0x002 e_cblp           : 0x90
   +0x004 e_cp             : 3
   +0x006 e_crlc           : 0
   +0x008 e_cparhdr        : 4
   +0x00a e_minalloc       : 0
   +0x00c e_maxalloc       : 0xffff
   +0x00e e_ss             : 0
   +0x010 e_sp             : 0xb8
   +0x012 e_csum           : 0
   +0x014 e_ip             : 0
   +0x016 e_cs             : 0
   +0x018 e_lfarlc         : 0x40
   +0x01a e_ovno           : 0
   +0x01c e_res            : [4] 0x0
   +0x024 e_oemid          : 0
   +0x026 e_oeminfo        : 0
   +0x028 e_res2           : [10] 0x0
   +0x03c e_lfanew         : 0n240 (= 0xF0)
```

Note: WinDbg displays `e_lfanew` as `0n240` (decimal 240 = 0xF0) because the field is typed
as `LONG` (signed). The `0n` prefix means decimal in WinDbg notation.

---

## Common Mistakes

### Mistake 1: Forgetting to Add ImageBase to `e_lfanew`

**The error**:
```nasm
; WRONG — treats e_lfanew as an absolute address
mov eax, [ebx + 0x3C]    ; EAX = 0x80 (the RVA, a small number)
mov ecx, [eax]            ; ACCESS VIOLATION — reading from address 0x80
```

**The correct approach**:
```nasm
; CORRECT — convert RVA to VA first
mov eax, [ebx + 0x3C]    ; EAX = 0x80 (RVA)
add eax, ebx             ; EAX = module_base + 0x80 (VA)
mov ecx, [eax]           ; reads IMAGE_NT_HEADERS signature correctly
```

`e_lfanew` is a file offset / RVA. It is a small integer like 0x40, 0x80, or 0xF0. It is NOT
a memory address. You cannot dereference it directly. This is perhaps the single most common
mistake in beginner PE-walking shellcode and causes an immediate access violation.

### Mistake 2: Assuming `e_lfanew` Is Always 0x40 or 0x80

**The error**: Hardcoding the NT headers offset:
```nasm
; WRONG — hardcoded offset
add ebx, 0x40             ; Assume NT headers at base + 0x40
cmp dword [ebx], 0x00004550
```

Different linker versions, compiler settings, and especially packers produce different `e_lfanew`
values. Some examples from real-world binaries:
- Windows system DLLs (MSVC): commonly 0xE8 or 0xF0
- MinGW compiled: commonly 0x80
- UPX packed: 0x80–0x100 range, variable
- Custom PE builders: any value whatsoever

Shellcode that hardcodes 0x40 will work on manually assembled test payloads and fail on production
system DLLs. Always read `e_lfanew` dynamically.

### Mistake 3: Confusing ASCII "MZ" with the WORD Value 0x4D5A vs 0x5A4D

**The confusion**: The ASCII string "MZ" consists of the bytes 0x4D ('M') followed by 0x5A ('Z').
When those two bytes are read as a 16-bit little-endian WORD by the x86 processor, the first byte
(0x4D) becomes the low byte and the second byte (0x5A) becomes the high byte:

```
Memory layout: [0x4D] [0x5A]
As WORD (little-endian): high=0x5A, low=0x4D → WORD value = 0x5A4D
```

The Windows SDK defines:
```c
#define IMAGE_DOS_SIGNATURE    0x5A4D      // MZ
```

**The error**:
```nasm
; WRONG — backwards comparison
cmp word [ebx], 0x4D5A    ; comparing against "MZ" as big-endian — FAILS
```

**The correct check**:
```nasm
; CORRECT — little-endian WORD comparison
cmp word [ebx], 0x5A4D    ; IMAGE_DOS_SIGNATURE
```

Alternatively, compare individual bytes to avoid the endianness issue entirely:
```nasm
cmp byte [ebx + 0], 'M'   ; 0x4D
jne .not_pe
cmp byte [ebx + 1], 'Z'   ; 0x5A
jne .not_pe
```

### Mistake 4: Not Validating the PE Signature After Reading `e_lfanew`

Walking the PEB module list gives you `DllBase` values that *should* be valid PE bases. However:
- Memory corruption can invalidate a DOS header
- Some entries in the loader list may be partially initialized
- Deliberately crafted images can have valid `e_magic` but corrupted `e_lfanew`

Always validate:
```nasm
mov eax, [ebx + 0x3C]      ; e_lfanew
add eax, ebx                ; VA of NT headers
cmp dword [eax], 0x00004550 ; "PE\0\0"
jne .skip                   ; not a valid PE, skip this module
```

### Mistake 5: Treating the DOS Header as the Entire PE Structure

Beginners sometimes look for export tables, section tables, or import tables starting from the
DOS header. The DOS header is only a 64-byte structure. Everything important — file header,
optional header, sections, directories — lives at `base + e_lfanew` and beyond. The DOS header's
only job is to contain `e_magic` (validity check) and `e_lfanew` (forward pointer).

---

## Exploit and Shellcode Relevance

### Position-Independent Code (PIC) Requirements

Shellcode must be position-independent — it cannot use hardcoded addresses because it is injected
at unknown locations. The DOS header is relevant because:

1. **Module discovery**: Shellcode finds module bases via the PEB loader data, then validates them
   using `e_magic` from the DOS header.

2. **PE chain traversal**: Every deeper PE structure (NT headers, optional header, data directories,
   export directory) is reached by starting at the module base and reading `e_lfanew`.

3. **Hash-based API resolution**: The classic technique for calling Windows APIs without
   hardcoded addresses works as follows:
   - Walk PEB to find module bases
   - Validate `e_magic` at each base
   - Read `e_lfanew` → NT headers → Optional header → Export directory
   - Walk the export table comparing hashed function names
   - Return the function VA

The DOS header is step one of this entire chain.

### Anti-Analysis and Evasion

- **Stub region for storage**: As described above, the region between offset 0x40 and `e_lfanew`
  can hold payload data, decryption keys, or configuration — invisible to section-based scanning.

- **`e_lfanew` manipulation**: Some evasion techniques involve shifting `e_lfanew` to an unusual
  offset to confuse automated PE parsers while remaining valid for the Windows loader.

- **Fake DOS headers**: A memory-only PE (e.g., a manually mapped shellcode payload) does not
  need a valid DOS stub — only `e_magic = 0x5A4D` and a correct `e_lfanew` are required for
  shellcode PE-walking to succeed.

### Summary: What Shellcode Needs from the DOS Header

| Requirement              | Field      | Action                         |
|--------------------------|------------|--------------------------------|
| Confirm valid PE module  | `e_magic`  | Compare to 0x5A4D              |
| Navigate to NT headers   | `e_lfanew` | Read + add to module base      |
| Everything else          | (ignored)  | Skip all other DOS header fields|

Two fields. One read. One add. That is the complete relevance of IMAGE_DOS_HEADER to shellcode.
