# IAT-Based Function Resolution (Evasion Technique)

## Overview

Instead of walking the PEB to find module bases and then traversing export tables
to resolve functions by hash, read function pointers directly from the target
process's Import Address Table (IAT). This avoids all hookable API calls and
well-known shellcode signatures.

## Minimum Requirements

- **GetProcAddress** and **LoadLibraryA** in the target's IAT
- Known IAT slot addresses (requires static analysis of the target binary)
- ASLR disabled for the target module, OR an information leak to derive the base

With just those two pointers, you can resolve any other function dynamically.

## Why It Evades Detection

| Technique | Observable Behavior |
|-----------|-------------------|
| PEB walk | Accesses `fs:[0x30]`, traverses `InMemoryOrderModuleList` -- signature-matched by EDR |
| GetProcAddress | Hits ntdll inline hooks placed by EDR |
| IAT read | Ordinary memory read at a fixed address -- no API call, no syscall, no hook surface |

## When to Use

- **Post-exploitation**: injecting into a known process during lateral movement
- **DLL sideloading**: targeting a specific application you've already profiled
- **Targeted implants**: when you know the host binary's PE layout in advance

## When NOT to Use

- Generic first-stage shellcode (don't know the host binary)
- ASLR-enabled targets without an info leak
- When you need portability across different target versions

## Workflow for Engagements

1. Recon: dump target binary imports (`dumpbin /imports target.exe`)
2. Confirm GetProcAddress + LoadLibraryA are imported from kernel32
3. Note the IAT RVA for each (offset from image base)
4. Confirm ASLR status for the module (`dumpbin /headers` -- check DllCharacteristics)
5. If ASLR off: `image_base + IAT_RVA = hardcoded pointer address`
6. If ASLR on: need a leak to derive image_base at runtime

## Bootstrap Sequence (Shellcode)

```asm
; Hardcoded IAT slot addresses (target-specific, ASLR off)
; These come from static analysis of the target binary
IAT_GetProcAddress equ 0x00XXYYZZ
IAT_LoadLibraryA   equ 0x00XXYYZZ

; Read function pointers directly -- no PEB walk, no export hash loop
mov  eax, [IAT_GetProcAddress]   ; eax = &GetProcAddress
mov  ebx, [IAT_LoadLibraryA]     ; ebx = &LoadLibraryA

; Now bootstrap anything:
; push "ws2_32.dll" ...
; call ebx                        ; LoadLibraryA -> module handle
; push "WSAStartup" ...
; push eax                        ; hModule
; call [saved_GetProcAddress]     ; resolve any export by name
```

## Size Comparison

| Technique | Approximate Size |
|-----------|-----------------|
| PEB walk + ROR13 hash resolver | ~80-100 bytes framework stubs |
| IAT direct read bootstrap | ~10-15 bytes (two mov instructions) |

The savings come from eliminating the entire PEB traversal, module list walk,
export directory parsing, and hash computation loop.

## Limitations

- Target-specific: IAT addresses change per binary/version
- Not position-independent without an info leak (ASLR)
- Requires pre-engagement reconnaissance of the target PE
- If the target is updated/patched, IAT offsets may shift

## Fallback: Single-Function Bootstrap

If only GetProcAddress is in the IAT (no LoadLibraryA):

1. Read GetProcAddress pointer from IAT
2. Scan backward from that address (page-aligned) to find kernel32's MZ header
3. `GetProcAddress(kernel32_base, "LoadLibraryA")` to get the second primitive
4. Proceed normally

Adds ~20 bytes for the backward MZ scan but still avoids the PEB walk.

## References

- OSED Module 3-4: PEB walk (standard technique this replaces)
- PE format: IMAGE_IMPORT_DESCRIPTOR and IAT structure
- EDR evasion: inline hooking of ntdll/kernel32 exports
