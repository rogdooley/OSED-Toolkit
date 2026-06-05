# Exercise 02 — LDR_DATA_TABLE_ENTRY Fields

## The question

For any given node in the module list, how do you extract the three fields
that matter: `DllBase`, `BaseDllName.Length`, and `BaseDllName.Buffer`?

---

## Setup

Continue from Exercise 01. You have the list head and can reach any entry.

---

## Step 1 — Pick a mid-list entry

Walk the list to find ntdll (it is typically the second entry in load order
on Windows 10). For each entry, read the name until you find it:

```
0:000> dd LDR_ADDR+0xc L1          ; first entry
0:000> du poi(result+0x30)
; follow Flink if not ntdll
0:000> dd result L1                ; second entry
0:000> du poi(result+0x30)
```

When you find ntdll, write down its entry address. Call it `NTDLL_ENTRY`.

---

## Step 2 — Read DllBase

`DllBase` is at `InLoadOrderLinks + 0x18`:

```
0:000> dd NTDLL_ENTRY+0x18 L1
```

Cross-check with `lm m ntdll`. The base addresses should match.

---

## Step 3 — Read BaseDllName (the UNICODE_STRING)

A `UNICODE_STRING` struct is three fields:

```c
typedef struct _UNICODE_STRING {
    USHORT Length;          // byte count (not char count)
    USHORT MaximumLength;
    PWSTR  Buffer;          // pointer to wide-char string
} UNICODE_STRING;
```

`BaseDllName` sits at `InLoadOrderLinks + 0x2c`:

```
; Read all three fields as consecutive WORDs/DWORD
0:000> dw NTDLL_ENTRY+0x2c L4
```

- Bytes 0–1 at `+0x2c`: `Length` in bytes
- Bytes 2–3 at `+0x2e`: `MaximumLength`
- Bytes 4–7 at `+0x30`: `Buffer` pointer (DWORD)

Or read them individually:

```
0:000> dw NTDLL_ENTRY+0x2c L1      ; Length (USHORT)
0:000> dd NTDLL_ENTRY+0x30 L1      ; Buffer pointer
```

---

## Step 4 — Verify Length vs. actual string

`ntdll.dll` has 9 characters. Unicode = 18 bytes. So `Length` should be
`0x12` (18).

Compute it yourself: count the characters in the expected DLL name, multiply
by 2 (UTF-16LE, 2 bytes per BMP character). That is the `Length` value your
shellcode must compare against to filter by name efficiently.

Check:

```
0:000> dw NTDLL_ENTRY+0x2c L1
```

Expected: `0012` (little-endian WORD = 0x0012 = 18).

---

## Step 5 — Follow the Buffer and read the string two ways

**With `du`:**

```
0:000> du poi(NTDLL_ENTRY+0x30)
```

`du` shows a Unicode (wide) string until a null terminator. Easy.

**Manually with `dw`:**

```
0:000> dw poi(NTDLL_ENTRY+0x30) L0xc   ; 12 WORDs = 24 bytes = "ntdll.dll" + some extra
```

You should see the wide characters: `006e 0074 0064 006c 006c 002e 0064 006c
006c 0000` — that's `n t d l l . d l l \0` in UTF-16LE.

**Why both matter:** shellcode doesn't use `du`. It reads DWORDs (two wide
chars at a time) and compares them. Understanding the raw byte layout is the
prerequisite for writing that comparison correctly.

---

## Step 6 — UNICODE_STRING length quirk

`UNICODE_STRING.Length` is the byte count of the string **not including** the
null terminator (even if one is present). `Buffer` may or may not have a null.
Code must use `Length` to bound comparisons, not scan for null.

Verify: count the bytes in `ntdll.dll`: 9 chars * 2 = 18 = `0x12`. Confirm
`Length = 0x12` in your read above.

For `KERNEL32.DLL`: 12 chars * 2 = 24 = `0x18`. This is the check
value used in the classic PEB-walking shellcode.

---

## Step 7 — Full entry dump with `dt`

```
0:000> dt ntdll!_LDR_DATA_TABLE_ENTRY NTDLL_ENTRY
```

Confirm every field you read manually matches the `dt` output.

Pay attention to `EntryPoint` — for DLLs, this is `DllMain`. For the main
executable it's the entry point you'd start from. It is used by shellcode that
wants to call a DLL's entry point directly (rare but exists).

---

## Checkpoint

1. `BaseDllName.Length` for `KERNEL32.DLL` is what decimal/hex value?
2. What does `dw addr L1` read vs `dd addr L1`?
3. `BaseDllName.Buffer` contains a null terminator — true or false? Does it
   matter?
4. Why would shellcode compare `BaseDllName.Length` before comparing the
   string itself?
5. From an `InLoadOrderLinks` pointer, write the three expressions that read
   `DllBase`, `BaseDllName.Length`, and `BaseDllName.Buffer`.

---

## Field summary (InLoadOrder offsets)

```
ENTRY+0x18   DllBase (4 bytes)
ENTRY+0x1c   EntryPoint (4 bytes)
ENTRY+0x20   SizeOfImage (4 bytes)
ENTRY+0x24   FullDllName.Length (USHORT)
ENTRY+0x26   FullDllName.MaximumLength (USHORT)
ENTRY+0x28   FullDllName.Buffer (PWSTR)
ENTRY+0x2c   BaseDllName.Length (USHORT)
ENTRY+0x2e   BaseDllName.MaximumLength (USHORT)
ENTRY+0x30   BaseDllName.Buffer (PWSTR)
```
