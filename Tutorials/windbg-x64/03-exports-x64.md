# Module 03 — PE Exports on x64

## The differences at a glance

The PE32+ (x64) format differs from PE32 (x86) in only a few key places:

| Item | PE32 (x86) | PE32+ (x64) |
|---|---|---|
| Optional Header Magic | `0x010b` | `0x020b` |
| ImageBase field | 4 bytes | 8 bytes |
| Optional Header size | 224 bytes | 240 bytes |
| DataDirectory offset | `OptHdr + 0x60` | `OptHdr + 0x70` |
| Export Dir RVA from NT header | `NT + 0x78` | `NT + 0x88` |

The export directory structure (`IMAGE_EXPORT_DIRECTORY`) itself is identical
in x86 and x64 — it uses RVAs (32-bit values), not full 64-bit pointers. This
is because PE files use RVAs everywhere they can for position-independence.

---

## Step 1 — Detecting PE32 vs PE32+ in the debugger

Read the Optional Header Magic:

```
0:000> dw <base + e_lfanew + 0x18> L1
; x86 PE32:  010b
; x64 PE32+: 020b
```

The osed-windbg toolkit reads this automatically:

```
0:000> dx @$osed().sc.pe("kernel32")
; look for "Machine" = x64 (0x8664) and "Optional Header Magic" = PE32+
```

---

## Step 2 — Finding the Export Directory RVA on x64

For PE32 (x86), the Export Directory RVA is at `NT_HEADER + 0x78`:
```
OptionalHeader starts at NT_HEADER + 0x18
DataDirectory[0].VirtualAddress at OptHdr + 0x60
Total: NT_HEADER + 0x18 + 0x60 = NT_HEADER + 0x78
```

For PE32+ (x64), DataDirectory starts at `OptHdr + 0x70` (not `+0x60`),
because ImageBase is 8 bytes instead of 4:
```
OptionalHeader starts at NT_HEADER + 0x18
DataDirectory[0].VirtualAddress at OptHdr + 0x70
Total: NT_HEADER + 0x18 + 0x70 = NT_HEADER + 0x88
```

Read the Export Directory RVA on x64:

```
0:000> dd <NT_HEADER + 0x88> L1    ; export dir RVA (still a 32-bit RVA)
```

---

## Step 3 — Everything below the Export Directory is the same

Once you have `EXPORT_DIR_VA`, the `IMAGE_EXPORT_DIRECTORY` structure is
identical between x86 and x64. All three arrays (AddressOfFunctions,
AddressOfNames, AddressOfNameOrdinals) contain 32-bit RVAs and 16-bit ordinal
indices, regardless of bitness.

The resolution algorithm:
1. Add each RVA to the 64-bit module base to get the VA
2. Use `poi()` in WinDbg — it automatically reads the pointer width appropriate
   to the current process context

```
0:000> da <K32_BASE + poi(AON_VA)>   ; still works on x64
```

---

## Step 4 — x64 shellcode difference: 8-byte base addition

The only change in the assembly is where you add the module base:

```asm
; x86: EAX = module base (32 bits)
add edx, eax    ; VA = RVA + 32-bit base

; x64: RAX = module base (64 bits)
add rdx, rax    ; VA = RVA + 64-bit base
; but rdx was loaded from a 32-bit RVA (mov edx, [...])
; mov edx zeroed the upper 32 bits of rdx — safe
```

x64 automatically zero-extends a 32-bit move into the full 64-bit register.
So `mov edx, [rax + 0x3c]` sets the full `rdx` to a 32-bit value (zero-
extended). Adding to `rax` (the 64-bit base) then produces a correct 64-bit
VA.

---

## Step 5 — Verify with osed-windbg on x64

Attach to a native 64-bit process. Run:

```
0:000> dx @$osed().sc.pe("kernel32")
0:000> dx @$osed().sc.exportwalk("kernel32", "LoadLibraryA")
```

Verify the `[4] NT header` address is correct, and that the export walk
reaches the same `LoadLibraryA` address as `x kernel32!LoadLibraryA`.

---

## x86/x64 offset comparison table

| Step | x86 expression | x64 expression |
|---|---|---|
| TEB → PEB | `poi(fs:[30])` | `poi(gs:[60])` |
| PEB → Ldr | `[PEB+0x0c]` | `[PEB+0x18]` |
| Ldr → InLoadOrder.Flink | `[LDR+0x0c]` | `[LDR+0x10]` |
| Entry → DllBase | `[ENTRY+0x18]` | `[ENTRY+0x30]` |
| Entry → BaseDllName.Buffer | `[ENTRY+0x30]` | `[ENTRY+0x60]` |
| Base → e_lfanew | `[BASE+0x3c]` | `[BASE+0x3c]` (same) |
| NT → Export Dir RVA | `[NT+0x78]` | `[NT+0x88]` |
| VA = RVA + base | `add edx, eax` | `add rdx, rax` |

The export directory fields themselves (once you have `EXPORT_DIR_VA`) are
identical in both architectures.

---

## Checkpoint (no reference)

1. Optional Header Magic for PE32+: `0x010b` or `0x020b`?
2. Export Directory RVA location from NT header: `+0x78` (x86) vs what (x64)?
3. `IMAGE_EXPORT_DIRECTORY.AddressOfFunctions` contains 32-bit or 64-bit RVAs?
4. In x64 shellcode, after `mov edx, [rax + rFuncRva*4]` (loading a 32-bit
   function RVA into edx), what instruction gives you the 64-bit VA?
5. A single PE binary can contain both a 32-bit and 64-bit export table.
   True or false?

---

## Summary: x86 → x64 migration checklist

When porting a PEB-walking shellcode from x86 to x64:

- [ ] Change `fs:[0x30]` → `gs:[0x60]`
- [ ] Change `[PEB+0x0c]` → `[PEB+0x18]` for Ldr
- [ ] Change `[LDR+0x0c]` → `[LDR+0x10]` for InLoadOrder.Flink
- [ ] Change `[ENTRY+0x18]` → `[ENTRY+0x30]` for DllBase
- [ ] Change `[ENTRY+0x30]` → `[ENTRY+0x60]` for BaseDllName.Buffer
- [ ] Change `[ENTRY+0x2c]` → `[ENTRY+0x58]` for BaseDllName.Length
- [ ] Change `[NT+0x78]` → `[NT+0x88]` for export dir RVA
- [ ] Change all `mov eX, [...]` pointer loads to `mov rX, [...]`
- [ ] Change all `add eX, eY` base additions to `add rX, rY`
- [ ] Remove `pushad`/`popad`, replace with explicit push/pop
- [ ] Ensure stack is 16-byte aligned before each `call`
