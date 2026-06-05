# Exercise 03 — Finding kernel32

## The question

Walk the module list from scratch and find `kernel32.dll` by comparing
`BaseDllName`. Record its `DllBase`. This is exactly what a shellcode PEB
walker does.

---

## Setup

Attach to any x86 process. Compute starting values:

```
0:000> dd fs:[30] L1               ; PEB
; R $t0 = PEB_ADDR

0:000> dd poi(fs:[30])+0xc L1      ; Ldr (PEB_LDR_DATA)
; R $t1 = LDR_ADDR
```

---

## The algorithm

```
1. LIST_HEAD = LDR_ADDR + 0x0c
2. CURRENT   = Flink of LIST_HEAD = [LIST_HEAD]
3. while CURRENT != LIST_HEAD:
     a. length = [CURRENT + 0x2c]  (BaseDllName.Length, USHORT)
     b. if length != 0x18: goto 4  (skip — not 24 bytes = "KERNEL32.DLL")
     c. buf    = [CURRENT + 0x30]  (BaseDllName.Buffer, PWSTR)
     d. compare first 12 bytes of *buf against L"KERNEL32.DLL"
     e. if match: return [CURRENT + 0x18]  (DllBase)
     f. CURRENT = [CURRENT]        (follow Flink)
4. return 0 (not found)
```

---

## Step 1 — Establish LIST_HEAD and first entry

```
; LIST_HEAD address (for termination check):
0:000> ? poi(poi(fs:[30])+0xc) + 0xc
; That expression: PEB_LDR_DATA + 0x0c = address of InLoadOrderModuleList
; Wait — that is wrong. LIST_HEAD is the address OF the field, not its value.
; Correct:
0:000> dd poi(fs:[30])+0xc L1     ; Ldr value
; r $t1 = Ldr value
```

The list head is the `LIST_ENTRY` field inside `PEB_LDR_DATA` at offset
`+0x0c`. Its address (not value) is `LDR_ADDR + 0x0c`. Call this `LIST_HEAD`.

First entry is `[LIST_HEAD]`:

```
0:000> dd LDR_ADDR+0xc L1         ; Flink = first entry address
; r $t2 = first entry address
```

---

## Step 2 — Filter by BaseDllName.Length

For `KERNEL32.DLL` the expected length is `0x18` (24 bytes, 12 wide chars).

Read the current entry's length:

```
0:000> dw CURRENT_ENTRY+0x2c L1
```

If not `0x18`: skip this entry and follow Flink.

---

## Step 3 — Compare the name

When length == `0x18`, read the Buffer pointer and compare the string.

In WinDbg you can read the string directly:

```
0:000> du poi(CURRENT_ENTRY+0x30)
```

Or compare the raw DWORDs as shellcode would (two wide chars per DWORD):

```
; "KE" in UTF-16LE: K=0x004B, E=0x0045 → DWORD = 0x0045004B
0:000> dd poi(CURRENT_ENTRY+0x30) L1
; expected: 0045004b

; "RN": R=0x0052, N=0x004E → DWORD = 0x004E0052
0:000> dd poi(CURRENT_ENTRY+0x30)+4 L1
; expected: 004e0052

; "EL": E=0x0045, L=0x004C → DWORD = 0x004C0045
0:000> dd poi(CURRENT_ENTRY+0x30)+8 L1
; expected: 004c0045

; "32": 3=0x0033, 2=0x0032 → DWORD = 0x00320033
0:000> dd poi(CURRENT_ENTRY+0x30)+0xc L1
; expected: 00320033

; ".D": .=0x002E, D=0x0044 → DWORD = 0x0044002E
0:000> dd poi(CURRENT_ENTRY+0x30)+0x10 L1
; expected: 0044002e

; "LL": L=0x004C, L=0x004C → DWORD = 0x004C004C
0:000> dd poi(CURRENT_ENTRY+0x30)+0x14 L1
; expected: 004c004c
```

If all six DWORDs match: you found kernel32.

---

## Step 4 — Extract DllBase

```
0:000> dd CURRENT_ENTRY+0x18 L1
```

Cross-check:

```
0:000> lm m kernel32
```

Both should show the same base address.

---

## Step 5 — Try the InInitializationOrderList walk

The initialization order list is what older shellcode uses. Walk it from
`LDR_ADDR+0x1c`:

```
0:000> dd LDR_ADDR+0x1c L1         ; InInitOrderModuleList.Flink = first entry
```

When you land on each entry, the offsets are **different** because your pointer
lands on `InInitializationOrderLinks` (offset `0x10` inside the entry) rather
than `InLoadOrderLinks` (offset `0x00`):

```
BaseDllName.Length  is at INIT_ENTRY + 0x1c   (not 0x2c)
BaseDllName.Buffer  is at INIT_ENTRY + 0x20   (not 0x30)
DllBase             is at INIT_ENTRY + 0x08   (not 0x18)
```

Walk this list until you find kernel32 using the shifted offsets. Confirm you
get the same `DllBase`.

**The list head for termination:** `LDR_ADDR + 0x1c` (address of the
`InInitializationOrderModuleList` field).

---

## Step 6 — Why InLoadOrder is preferred for modern shellcode

Walk both lists and observe the order:

- InInitializationOrderList on Windows XP/7: `[ntdll, kernel32, ...]`
- InInitializationOrderList on Windows 10: contains many more entries before
  kernel32 due to KernelBase.dll, API set DLLs, etc.

The initialization list order is non-deterministic across Windows versions.
The load order list (`InLoadOrderModuleList`) starts with the executable itself
then ntdll then kernel32, which is more consistent — but even that varies.
The only safe approach is to walk the complete list and compare names.

---

## Checkpoint

1. What are the DWORD values for "KE", "RN", "EL", "32", ".D", "LL" in
   UTF-16LE little-endian?
2. When using InInitializationOrderList, what offset gives DllBase from the
   current entry pointer?
3. Why is checking `BaseDllName.Length == 0x18` a useful pre-filter before
   comparing the full name?
4. What does the case-insensitive trick `or eax, 0x00200020` do in assembly,
   and why doesn't it work on digits and the dot character?
5. After finding kernel32, what single DWORD read gives you its base address?

---

## Writeup prompt

Write the complete PEB walk algorithm in pseudocode, using the InLoadOrder
list. Label every step with the field name and offset. Do not look at any
reference while writing. If you get a step wrong, fix it and note what you
got wrong — that is the mistake your shellcode will make on the first attempt.
