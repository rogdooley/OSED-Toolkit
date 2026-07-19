# 18. PE Structures and Export Resolution

## Header Chain

```
DllBase
  +0x00   IMAGE_DOS_HEADER
    +0x00   e_magic     ("MZ" = 0x5A4D)
    +0x3C   e_lfanew    (offset to NT headers)

DllBase + e_lfanew
  +0x00   Signature    ("PE\0\0" = 0x00004550)
  +0x04   IMAGE_FILE_HEADER  (20 bytes)
  +0x18   IMAGE_OPTIONAL_HEADER32
    +0x60   DataDirectory[0] = Export Directory
      +0x00   VirtualAddress (RVA of IMAGE_EXPORT_DIRECTORY)
      +0x04   Size
```

Export Directory RVA is at: `DllBase + e_lfanew + 0x78`

## IMAGE_EXPORT_DIRECTORY

| Offset | Field | Meaning |
|--------|-------|---------|
| +0x18 | NumberOfNames | Count of named exports |
| +0x1C | AddressOfFunctions | RVA of function address table (array of RVAs) |
| +0x20 | AddressOfNames | RVA of name pointer table (array of RVAs to strings) |
| +0x24 | AddressOfNameOrdinals | RVA of ordinal table (array of 16-bit ordinals) |

## Resolution Algorithm

1. **Locate module base** (from PEB walk or known address)
2. **Read e_lfanew:** `pe_offset = [base + 0x3C]`
3. **Locate PE header:** `pe_header = base + pe_offset`
4. **Locate export directory RVA:** `export_rva = [pe_header + 0x78]`
5. **Compute export directory VA:** `exports = base + export_rva`
6. **Get table pointers:**
   - `names = base + [exports + 0x20]`
   - `ordinals = base + [exports + 0x24]`
   - `functions = base + [exports + 0x1C]`
7. **Iterate names:** For index `i`, name string is at `base + [names + i*4]`
8. **Match target name** (compare string or hash)
9. **Get ordinal:** `ordinal = [ordinals + i*2]` (16-bit value)
10. **Get function RVA:** `func_rva = [functions + ordinal*4]`
11. **Compute function VA:** `func_va = base + func_rva`

## Assembly Implementation

```asm
; Assume EBX = module base
mov edx, [ebx+0x3C]         ; e_lfanew
add edx, ebx                ; PE header VA
mov edx, [edx+0x78]         ; export directory RVA
add edx, ebx                ; export directory VA
mov ecx, [edx+0x18]         ; NumberOfNames
mov eax, [edx+0x20]         ; AddressOfNames RVA
add eax, ebx                ; AddressOfNames VA

; Loop through names
find_function:
    dec ecx
    mov esi, [eax+ecx*4]    ; name RVA
    add esi, ebx             ; name VA
    ; compare string at ESI with target (or compute hash)
    ; if match: ecx = index
    ; ...

; Resolve address using ordinal
    mov eax, [edx+0x24]     ; AddressOfNameOrdinals RVA
    add eax, ebx
    movzx ecx, word ptr [eax+ecx*2]  ; ordinal
    mov eax, [edx+0x1C]     ; AddressOfFunctions RVA
    add eax, ebx
    mov eax, [eax+ecx*4]    ; function RVA
    add eax, ebx             ; function VA
```

## Forwarded Exports

If a function RVA falls within the export directory's address range, it is a
**forwarded export** -- the RVA points to a string like `"NTDLL.RtlAllocateHeap"`
instead of code. The resolver must parse this string, load the target module,
and re-resolve. Shellcode that encounters a forward must handle it or avoid
APIs known to be forwarded.

## API Sets (Conceptual)

On Windows 8+, some DLL names are virtualized through API sets (e.g.,
`api-ms-win-core-*.dll` maps to `KernelBase.dll`). The loader resolves these
transparently, but shellcode that walks the module list may encounter API set
entries. They are not real DLLs -- the actual code lives in a backing DLL
(typically KernelBase.dll or ntdll.dll).
