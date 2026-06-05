# Exercise 03 — Resolving a Function by Name

## The question

Given kernel32's base address and the target name `WinExec`, walk the three
export arrays manually and arrive at the function's virtual address.

---

## Setup

You have `K32_BASE`, `EXPORT_DIR_VA`, `AOF_VA`, `AON_VA`, `AONO_VA` from
Exercise 02.

Target: `WinExec`.

---

## Step 1 — Linear search (proof of concept)

A production shellcode uses a hash comparison for speed, but for learning we
do a linear search with manual name comparisons.

Read entries from `AON_VA` until you find `WinExec`:

```
0:000> da K32_BASE + poi(AON_VA + 0*4)   ; entry 0
0:000> da K32_BASE + poi(AON_VA + 1*4)   ; entry 1
0:000> da K32_BASE + poi(AON_VA + 2*4)   ; entry 2
; ... continue until you see WinExec
```

This would take forever manually (kernel32 has 1400+ exports). Instead, use
WinDbg's search to find the name string in memory first:

```
0:000> s -a K32_BASE EXPORT_DIR_VA+100000 "WinExec"
```

This searches the ASCII string `WinExec` in the module's memory range. You'll
get one or more hits. One of those hits is the name string in the names table.

Note its address. Call it `WINEXEC_NAME_VA`.

---

## Step 2 — Find the names-table index

The name VA you found is in the module's string section. The names-table entry
pointing to it is at some `AON_VA[i]` such that
`K32_BASE + AON_VA[i] == WINEXEC_NAME_VA`.

Therefore: `AON_VA[i] == WINEXEC_NAME_VA - K32_BASE == WINEXEC_NAME_RVA`.

Search the `AON_VA` array for that RVA value:

```
0:000> ? WINEXEC_NAME_VA - K32_BASE     ; compute the RVA
; call it WINEXEC_NAME_RVA

0:000> s -d AON_VA AON_VA+NumberOfNames*4 WINEXEC_NAME_RVA
```

This searches for the DWORD value `WINEXEC_NAME_RVA` in the names array.
The hit address is `AON_VA + i*4`. Compute `i`:

```
0:000> ? (HIT_ADDRESS - AON_VA) / 4
; call this INDEX_I
```

---

## Step 3 — Look up the ordinal index

```
0:000> dw AONO_VA + INDEX_I*2 L1
; call this ORDINAL_IDX (it's a WORD)
```

---

## Step 4 — Look up the function RVA

```
0:000> dd AOF_VA + ORDINAL_IDX*4 L1
; call this FUNC_RVA
```

---

## Step 5 — Compute the VA

```
0:000> ? K32_BASE + FUNC_RVA
; call this WINEXEC_VA
```

---

## Step 6 — Verify

```
0:000> u WINEXEC_VA L3
```

You should see the beginning of `WinExec`'s code. If you see garbage, recheck
your arithmetic.

Cross-check with symbol lookup:

```
0:000> x kernel32!WinExec
```

Both addresses should match exactly.

---

## Step 7 — Repeat for `VirtualProtect`

Without looking at these notes, resolve `VirtualProtect` using the same
procedure. This function is critical in OSED's ROP/DEP bypass scenarios — it
is the typical target for a ROP chain that marks the stack executable.

```
target = "VirtualProtect"
```

Record the VA in your notes.

---

## Step 8 — The `exportwalk` shortcut

The osed-windbg toolkit has a command that shows every step of the resolution
walk with the actual values from memory:

```
0:000> dx @$osed().sc.exportwalk("kernel32", "WinExec")
```

Expected output (values will vary by Windows version):

```
[0]  Resolving         = WinExec
[1]  [1] Module base   = 0x76XXXXXX
[2]  [2] DOS header    = 0x76XXXXXX
[3]  [3] DOS.e_lfanew  = 0xF8
[4]  [4] NT header     = 0x76XXXXXXF8
[5]  [5] Export directory = 0x76XX...
[6]  [6] AddressOfNames   = 0x76XX...
[7]  [7] AddressOfNameOrdinals = 0x76XX...
[8]  [8] AddressOfFunctions    = 0x76XX...
[9]  [9] Match index   = 1234: WinExec
[10] [10] Ordinal index = 1232
[11] [11] Function RVA  = 0x000XXXXX
[12] [12] Final VA      = 0x76XXXXXX
[13] [13] Forwarded     = false
```

Cross-check every numbered step against your manual walk. They should match
exactly.

Also verify with the direct export lookup:

```
0:000> dx @$osed().sc.export("kernel32", "WinExec")
```

---

## Step 9 — Forwarded exports

Some kernel32 exports are forwarded to `KernelBase.dll`. The `exportwalk`
output shows `Forwarded = true` for those. A forwarded export has a function
RVA that points inside the export directory's address range (not to code) — the
bytes there are an ASCII string like `KERNELBASE.WinExec` naming the true
implementation.

Find a forwarded export:

```
0:000> dx @$osed().sc.exports("kernel32")
```

Look for entries where the VA seems to point inside the export directory range
(`K32_BASE + EXPORT_DIR_RVA` to `K32_BASE + EXPORT_DIR_RVA + EXPORT_DIR_SIZE`).
Read those bytes with `da` — you'll see the forwarded-to string.

---

## Checkpoint

1. Write the three-step formula: given `index_i`, how do you get the
   function's VA?
2. `AddressOfNameOrdinals` contains WORDs. Why is this important in your
   arithmetic (`*2` vs `*4`)?
3. A function RVA falls inside the export directory's address range. What
   does this mean?
4. How would you modify the linear search to be case-insensitive?
5. Run `x kernel32!WinExec` and `dx @$osed().sc.export("kernel32","WinExec")`.
   Do both show the same address?

---

## The complete x86 resolution algorithm

```
EAX = module base

; Step 1: NT header
MOV  EBX, [EAX+0x3c]     ; e_lfanew
ADD  EBX, EAX            ; NT_HEADER

; Step 2: Export directory
MOV  EDX, [EBX+0x78]     ; export dir RVA
ADD  EDX, EAX            ; export dir VA

; Step 3: Array pointers
MOV  ECX, [EDX+0x18]     ; NumberOfNames
MOV  EBX, [EDX+0x20]     ; AddressOfNames RVA
ADD  EBX, EAX            ; AddressOfNames VA

; Step 4: Linear name search
; (production code uses hash comparison — see Module 05)
; for i=0..ECX:
;   if strcmp(base + AON[i], target) == 0: found at index i

; Step 5: Ordinal index
MOV  EBX, [EDX+0x24]     ; AddressOfNameOrdinals RVA
ADD  EBX, EAX            ; VA
MOVZX EBX, WORD [EBX + i*2]  ; ordinal_index (WORD)

; Step 6: Function RVA
MOV  EDX, [EDX+0x1c]     ; AddressOfFunctions RVA
ADD  EDX, EAX            ; VA
MOV  EDX, [EDX + EBX*4]  ; function RVA

; Step 7: VA
ADD  EDX, EAX            ; function VA — DONE
```
