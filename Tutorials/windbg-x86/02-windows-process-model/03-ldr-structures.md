# Exercise 03 — Ldr Structures

## The question

The PEB's `Ldr` field points to `PEB_LDR_DATA`. Inside that structure are
three doubly-linked lists of loaded modules. What do those lists contain, how
are they threaded together, and how do you navigate them?

This exercise covers the data structures. Module 03 covers walking them to
find a specific DLL.

---

## Setup

Continue from Exercise 02. You have `LDR_ADDR` from `dd PEB_ADDR+0xc L1`.

If starting fresh:

```
0:000> dd fs:[30] L1             ; PEB_ADDR
0:000> dd poi(fs:[30])+0xc L1   ; LDR_ADDR
```

---

## Step 1 — Dump PEB_LDR_DATA with `dt`

```
0:000> dt ntdll!_PEB_LDR_DATA LDR_ADDR
```

You will see something like:

```
ntdll!_PEB_LDR_DATA
   +0x000 Length                : 0x30
   +0x004 Initialized           : 0x1 ''
   +0x008 SsHandle              : (null)
   +0x00c InLoadOrderModuleList : _LIST_ENTRY [ 0x2a6fc8 - 0x2b1cd0 ]
   +0x014 InMemoryOrderModuleList : _LIST_ENTRY [ 0x2a6fd0 - 0x2b1cd8 ]
   +0x01c InInitializationOrderModuleList : _LIST_ENTRY [ 0x2a6f38 - 0x2b1ce0 ]
```

Three lists. Each is a `LIST_ENTRY` (two DWORDs: Flink and Blink). The
`[Flink - Blink]` notation WinDbg shows is the address range of the circular
list — `Flink` of the head = first entry, `Blink` of the head = last entry.

---

## Step 2 — Understand `LIST_ENTRY`

`LIST_ENTRY` is Windows' generic doubly-linked circular list node:

```c
typedef struct _LIST_ENTRY {
    struct _LIST_ENTRY *Flink;   // forward link → next entry
    struct _LIST_ENTRY *Blink;   // backward link → previous entry
} LIST_ENTRY;
```

Key property: **the list is circular**. The last entry's `Flink` points back
to the list head (inside `PEB_LDR_DATA`). The head's `Blink` points to the
last entry. Walking the list ends when `Flink` equals the head address.

Each `LDR_DATA_TABLE_ENTRY` embeds three `LIST_ENTRY` fields — one per
ordering. When you follow `Flink` from a list head, you land on the
`LIST_ENTRY` field *embedded inside* an `LDR_DATA_TABLE_ENTRY`, not at the
start of the entry. You must account for this offset when reading other fields.

---

## Step 3 — PEB_LDR_DATA layout (x86)

```
Offset  Size  Field
0x00    4     Length
0x04    4     Initialized
0x08    4     SsHandle
0x0c    8     InLoadOrderModuleList           (LIST_ENTRY: Flink + Blink)
0x14    8     InMemoryOrderModuleList         (LIST_ENTRY)
0x1c    8     InInitializationOrderModuleList (LIST_ENTRY)   <-- classic walk
```

Read the `InLoadOrderModuleList.Flink` manually:

```
0:000> dd LDR_ADDR+0x0c L1
```

Call this `FIRST_LOAD_ENTRY`. This is a pointer to the first
`LDR_DATA_TABLE_ENTRY.InLoadOrderLinks`.

Read `InInitializationOrderModuleList.Flink`:

```
0:000> dd LDR_ADDR+0x1c L1
```

Call this `FIRST_INIT_ENTRY`. This is a pointer to the first
`LDR_DATA_TABLE_ENTRY.InInitializationOrderLinks`.

---

## Step 4 — LDR_DATA_TABLE_ENTRY layout (x86)

```
Offset  Size  Field
0x00    8     InLoadOrderLinks          (LIST_ENTRY)  <-- load list nodes here
0x08    8     InMemoryOrderLinks        (LIST_ENTRY)
0x10    8     InInitializationOrderLinks (LIST_ENTRY) <-- init list nodes here
0x18    4     DllBase
0x1c    4     EntryPoint
0x20    4     SizeOfImage
0x24    8     FullDllName               (UNICODE_STRING: Length, MaxLength, Buffer)
0x2c    8     BaseDllName               (UNICODE_STRING)
```

If you followed `InLoadOrderModuleList.Flink`, your pointer lands at the
`InLoadOrderLinks` field (offset `0x00`). So to read `DllBase`:

```
[pointer + 0x18]   → DllBase   (from InLoadOrderLinks + 0x18)
[pointer + 0x2c]   → BaseDllName.Length  (USHORT)
[pointer + 0x30]   → BaseDllName.Buffer  (PWSTR)
```

If you followed `InInitializationOrderModuleList.Flink`, your pointer lands at
the `InInitializationOrderLinks` field (offset `0x10`). The offsets are
**shifted by 0x10**:

```
[pointer + 0x08]   → DllBase   (from InInitOrderLinks + 0x08)
[pointer + 0x1c]   → BaseDllName.Length  (USHORT, note: +0x1c from InInitLinks)
[pointer + 0x20]   → BaseDllName.Buffer  (PWSTR)
```

This offset difference is the most common bug when first writing a PEB walker.
Know which list you are following and use the right offsets.

---

## Step 5 — Read the first entry via `dt`

```
0:000> dt ntdll!_LDR_DATA_TABLE_ENTRY FIRST_LOAD_ENTRY
```

Note the `DllBase` and `BaseDllName` fields. `BaseDllName.Buffer` is a
pointer to a Unicode (wide) string. Read it:

```
0:000> du poi(FIRST_LOAD_ENTRY + 0x30)
```

`du` displays a null-terminated Unicode string. You should see the name of the
first loaded module (typically `stack_lab_x86.exe` for load order).

---

## Step 6 — Read the first entry manually (no `dt`)

```
; DllBase at InLoadOrderLinks + 0x18
0:000> dd FIRST_LOAD_ENTRY+0x18 L1

; BaseDllName.Length at InLoadOrderLinks + 0x2c (USHORT = 2 bytes)
0:000> dw FIRST_LOAD_ENTRY+0x2c L1

; BaseDllName.Buffer at InLoadOrderLinks + 0x30
0:000> dd FIRST_LOAD_ENTRY+0x30 L1

; Follow BaseDllName.Buffer to read the name
0:000> du poi(FIRST_LOAD_ENTRY+0x30)
```

Cross-check the `DllBase` against `lm`. They should match.

---

## Step 7 — Walk two entries by hand

Follow `Flink` to the next entry:

```
0:000> dd FIRST_LOAD_ENTRY L1          ; [offset 0x00] = Flink to second entry
```

Call the second entry pointer `SECOND_LOAD_ENTRY`. Repeat the manual read:

```
0:000> du poi(SECOND_LOAD_ENTRY+0x30)   ; module name
0:000> dd SECOND_LOAD_ENTRY+0x18 L1    ; DllBase
```

Repeat once more for the third entry. You should see three module names — the
main executable, ntdll, and kernel32 (or some variation depending on load
order).

---

## Checkpoint

Answer in your notes:

1. What is `LIST_ENTRY` and how is the list terminated?
2. `InLoadOrderModuleList.Flink` points to what field in
   `LDR_DATA_TABLE_ENTRY`?
3. If your pointer came from following `InInitializationOrderLinks`, what
   offset gives you `DllBase`? What about `BaseDllName.Buffer`?
4. `BaseDllName.Length` is in bytes or characters? What is the value for
   `KERNEL32.DLL` (12 characters)?
5. Why is the "skip N entries" trick for finding kernel32 unreliable on
   Windows 8+?

---

## Offset cheat sheet — module walk via InLoadOrderModuleList

```
PEB_LDR_DATA:
  +0x0c   InLoadOrderModuleList.Flink     (→ first InLoadOrderLinks)
  +0x14   InMemoryOrderModuleList.Flink
  +0x1c   InInitializationOrderModuleList.Flink

From InLoadOrderLinks (offset 0x00 in entry):
  +0x18   DllBase
  +0x2c   BaseDllName.Length (USHORT)
  +0x2e   BaseDllName.MaximumLength (USHORT)
  +0x30   BaseDllName.Buffer (PWSTR)

From InInitOrderLinks (offset 0x10 in entry):
  +0x08   DllBase
  +0x1c   BaseDllName.Length (USHORT)
  +0x20   BaseDllName.Buffer (PWSTR)
```

The complete walk sequence (using InLoadOrder — preferred):

```asm
mov eax, fs:[0x30]        ; PEB
mov eax, [eax + 0x0c]     ; Ldr (PEB_LDR_DATA)
mov esi, [eax + 0x0c]     ; InLoadOrderModuleList.Flink
; ESI now points to InLoadOrderLinks of first entry
; [esi + 0x18] = DllBase
; [esi + 0x30] = BaseDllName.Buffer (wide string pointer)
; [esi]        = Flink → next entry (follow to walk list)
```
