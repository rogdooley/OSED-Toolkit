# Exercise 01 — DOS Header and NT Header

## The question

Given a module's base address, how do you locate the NT header, verify the
PE signature, and reach the Optional Header?

---

## Setup

Find kernel32's base address:

```
0:000> dd LDR_ADDR+0xc L1          ; first entry
; walk until kernel32 — or:
0:000> dx @$osed().sc.base("kernel32")
```

Call the result `K32_BASE`.

---

## Step 1 — The MZ signature

The very first two bytes of any PE image are `MZ` (0x4D 0x5A — the initials
of Mark Zbikowski, one of the MS-DOS designers). In WinDbg:

```
0:000> dw K32_BASE L1
```

Expected: `5A4D` — that is `0x4D` followed by `0x5A`, displayed as a
little-endian WORD = `0x5A4D`. The letters `MZ`.

If you see anything else, `K32_BASE` is not pointing at the start of a PE image.

---

## Step 2 — The DOS header and `e_lfanew`

The first 64 bytes of a PE image form the `IMAGE_DOS_HEADER`. The only field
that matters for PE parsing is `e_lfanew` at offset `+0x3c`:

```c
typedef struct _IMAGE_DOS_HEADER {
    WORD e_magic;       // "MZ" = 0x5A4D  [+0x00]
    ...                 // 28 fields you do not care about
    LONG e_lfanew;      // file offset of new exe header  [+0x3c]
} IMAGE_DOS_HEADER;
```

Read it:

```
0:000> dd K32_BASE+0x3c L1
```

Call this value `E_LFANEW`. It is a file offset (RVA from image base) to the
NT headers. Typical values: `0xd8`, `0xf0`, `0x100` — varies by linker.

---

## Step 3 — The NT header

The NT header starts at `K32_BASE + E_LFANEW`:

```
0:000> ? K32_BASE + E_LFANEW
; call this NT_HEADER
0:000> dd NT_HEADER L1
```

Expected first DWORD: `0x00004550` = ASCII "PE\0\0" (P=0x50, E=0x45).

This is the `Signature` field of `IMAGE_NT_HEADERS`. If you don't see
`00004550`, the `e_lfanew` was wrong or the image is not a standard PE.

---

## Step 4 — File Header (COFF header)

Immediately after the 4-byte `Signature` is the `IMAGE_FILE_HEADER`:

```
Offset from NT_HEADER:
  +0x04   Machine          (WORD)  — 0x014c = x86, 0x8664 = x64
  +0x06   NumberOfSections (WORD)
  +0x08   TimeDateStamp    (DWORD)
  +0x0c   PointerToSymbolTable (DWORD)
  +0x10   NumberOfSymbols  (DWORD)
  +0x14   SizeOfOptionalHeader (WORD)
  +0x16   Characteristics  (WORD)
```

Read the Machine field:

```
0:000> dw NT_HEADER+0x4 L1
```

Expected for x86: `014c`.

---

## Step 5 — Optional Header

The Optional Header starts at `NT_HEADER + 0x18`. For PE32 (x86), the first
WORD is `Magic = 0x010b`. For PE32+ (x64), it is `0x020b`.

```
0:000> dw NT_HEADER+0x18 L1
```

Expected for x86 kernel32: `010b`.

The Optional Header contains the data directories — an array of
`(RVA, Size)` pairs indexed by type. The first data directory (`index 0`) is
the Export Directory. Its RVA and size are at:

```
; DataDirectory array starts at Optional Header + 0x60 (for PE32)
; Export Directory = DataDirectory[0]
; RVA  is at Optional Header + 0x60
; Size is at Optional Header + 0x64

0:000> dd NT_HEADER+0x18+0x60 L2
```

First DWORD: `EXPORT_DIR_RVA`. Second DWORD: `EXPORT_DIR_SIZE`.

Write both down. The export directory is at `K32_BASE + EXPORT_DIR_RVA`.

---

## Step 6 — Putting it in assembly terms

Shellcode to reach the Export Directory RVA:

```asm
; EAX = kernel32 base
mov ebx, [eax + 0x3c]           ; e_lfanew
mov ebx, eax                     ; NT_HEADER base — wrong, needs adding
add ebx, [eax + 0x3c]           ; NT_HEADER = base + e_lfanew (ebx = NT_HEADER)
mov edx, [ebx + 0x78]           ; Export Directory RVA
                                 ; Wait — that's 0x18 (OptHdr) + 0x60 = 0x78 from NT_HEADER
```

Shortcut: the Export Directory RVA is at `NT_HEADER + 0x78`:

```
NT_HEADER + 0x18 (OptionalHeader start)
          + 0x60 (DataDirectory[0].VirtualAddress offset within OptHdr)
          = NT_HEADER + 0x78
```

Verify:

```
0:000> dd NT_HEADER+0x78 L1
```

Should match the `EXPORT_DIR_RVA` you read earlier.

---

## Verify with osed-windbg

```
0:000> dx @$osed().sc.pe("kernel32")
```

This outputs all PE header fields including `ExportDir RVA`. Cross-check
your manually-computed value.

---

## Checkpoint

1. What two-byte signature is at the start of every PE image?
2. What field in the DOS header gives the offset to the NT headers?
3. What is the PE signature (4 bytes) at the NT header?
4. The Export Directory RVA is at `NT_HEADER + N`. What is N?
5. What WinDbg command dumps the NT headers without manual arithmetic?
   (Hint: `dt ntdll!_IMAGE_NT_HEADERS`)

---

## Offset summary (x86 PE32)

```
[base + 0x00]       MZ signature (WORD = 0x5A4D)
[base + 0x3c]       e_lfanew  → offset to NT header
[base + e_lfanew]   PE signature (DWORD = 0x4550)
[base + e_lfanew + 0x04]  Machine (WORD: 0x014c = x86)
[base + e_lfanew + 0x78]  Export Directory RVA
[base + e_lfanew + 0x7c]  Export Directory Size
```

Assembly shorthand (EAX = module base):

```asm
mov ebx, [eax + 0x3c]    ; e_lfanew
add ebx, eax             ; ebx = NT header
mov edx, [ebx + 0x78]    ; Export Directory RVA
add edx, eax             ; edx = Export Directory VA
```
