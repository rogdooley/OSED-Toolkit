# Exercise 01 — The Linked-List Walk

## The question

Given the head of `InLoadOrderModuleList`, how do you walk every entry in the
list, and how do you know when you have reached the end?

---

## Setup

Attach to any x86 process. Compute the list head address:

```
0:000> dd fs:[30] L1                ; PEB_ADDR
; let PEB_ADDR = result

0:000> dd PEB_ADDR+0xc L1           ; Ldr (PEB_LDR_DATA)
; let LDR_ADDR = result

; The InLoadOrderModuleList is at LDR_ADDR+0x0c (two DWORDs: Flink, Blink)
; The list head address itself:
0:000> ? LDR_ADDR+0x0c
; call this LIST_HEAD
```

Write `LIST_HEAD` down. This is the sentinel address — when `Flink` equals
`LIST_HEAD`, you have completed one full traversal.

---

## Step 1 — First entry

```
0:000> dd LDR_ADDR+0xc L1          ; Flink of list head = first entry
; call this ENTRY_0
```

`ENTRY_0` is the `InLoadOrderLinks.Flink` pointer of the first
`LDR_DATA_TABLE_ENTRY`. Read the first DLL name:

```
0:000> du poi(ENTRY_0+0x30)         ; BaseDllName.Buffer
```

---

## Step 2 — Second entry

Follow `Flink` from `ENTRY_0`:

```
0:000> dd ENTRY_0 L1               ; Flink → second entry
; call this ENTRY_1
```

Read the second name:

```
0:000> du poi(ENTRY_1+0x30)
```

---

## Step 3 — Continue until back at LIST_HEAD

Repeat the pattern. After several entries:

```
0:000> dd ENTRY_N L1               ; Flink
```

When the Flink value equals `LIST_HEAD`, you have looped back to the head.
Stop. The next `Flink` from the head would take you back to `ENTRY_0`.

**How many entries do you have?** Count them. On a typical Windows 10 process
there will be 60+ entries for a fully-loaded process (all the API set DLLs,
Visual C++ runtime, etc.).

---

## Step 4 — The termination check explained

In shellcode, the termination check is:

```asm
lea ebx, [eax+0x0c]    ; EBX = address of InLoadOrderModuleList in PEB_LDR_DATA
                       ; = LIST_HEAD

.loop:
  cmp esi, ebx         ; current Flink == LIST_HEAD?
  je  .not_found       ; yes → wrapped around, target not found
  ; ... read name, compare ...
  mov esi, [esi]       ; follow Flink
  jmp .loop
```

The critical insight: `ebx` holds the **address of the LIST_ENTRY head in
PEB_LDR_DATA** (not the value at that address, but the address of the field
itself). When the current pointer `esi` equals that address, you've completed
a full traversal.

A null check (`test esi, esi; jz ...`) is weaker — it only catches a corrupt
list, not a missing module.

---

## Step 5 — WinDbg script version (automated walk)

WinDbg's pseudo-register system lets you script the walk. This is not required
to understand the algorithm, but it's useful for verification:

```
; Store list head
r $t0 = poi(poi(fs:[30])+0xc) + 0xc   ; LIST_HEAD = LDR_ADDR + 0x0c

; Get first entry
r $t1 = poi(poi(poi(fs:[30])+0xc)+0xc)

; Print name of first entry
du poi(@$t1+0x30)

; Follow Flink to second entry
r $t1 = poi(@$t1)

; Print second entry name
du poi(@$t1+0x30)
```

Walk manually as many times as needed until the pattern is automatic.

---

## Checkpoint

1. What value does `Flink` hold when the walk has completed the full circle?
2. What is the address you compare against for termination?
3. What WinDbg command reads a Unicode (wide) string?
4. Why is checking `Flink == NULL` an insufficient termination condition?
5. What are the two DWORDs at every `LIST_ENTRY`?
