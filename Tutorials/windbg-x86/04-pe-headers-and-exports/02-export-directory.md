# Exercise 02 — The Export Directory

## The question

Given the export directory address, how do you read it and understand the
relationship between the three arrays it contains?

---

## Setup

Continue from Exercise 01. You have:
- `K32_BASE` — kernel32 base address
- `EXPORT_DIR_RVA` — from `[NT_HEADER + 0x78]`
- `EXPORT_DIR_VA` = `K32_BASE + EXPORT_DIR_RVA`

---

## Step 1 — IMAGE_EXPORT_DIRECTORY layout

```
Offset  Size  Field
0x00    4     Characteristics       (reserved)
0x04    4     TimeDateStamp
0x08    2     MajorVersion
0x0a    2     MinorVersion
0x0c    4     Name                  (RVA of DLL name string)
0x10    4     Base                  (ordinal base — first ordinal number)
0x14    4     NumberOfFunctions     (total function count)
0x18    4     NumberOfNames         (number of named exports)
0x1c    4     AddressOfFunctions    (RVA → array of function RVAs)
0x20    4     AddressOfNames        (RVA → array of name RVAs)
0x24    4     AddressOfNameOrdinals (RVA → array of ordinal indices)
```

Read the whole directory:

```
0:000> dd EXPORT_DIR_VA L0xa
```

Ten DWORDs = the full directory.

---

## Step 2 — Read key fields

**DLL name** (RVA at `+0x0c`):

```
0:000> da K32_BASE + poi(EXPORT_DIR_VA+0x0c)
```

`da` displays an ASCII string. Should show `KERNEL32.dll`.

**Ordinal base** (`+0x10`):

```
0:000> dd EXPORT_DIR_VA+0x10 L1
```

Typically `1`. Ordinal numbers start at this value. If a function is at
ordinal index 0 in the functions array, its actual ordinal is
`Base + 0 = 1`.

**NumberOfFunctions** (`+0x14`) and **NumberOfNames** (`+0x18`):

```
0:000> dd EXPORT_DIR_VA+0x14 L2
```

`NumberOfFunctions` is the size of the `AddressOfFunctions` array.
`NumberOfNames` is the size of the `AddressOfNames` and
`AddressOfNameOrdinals` arrays. They are not the same: some functions are
exported by ordinal only (no name), making `NumberOfFunctions` ≥
`NumberOfNames`.

---

## Step 3 — The three arrays

Read the three array pointers (RVAs):

```
0:000> dd EXPORT_DIR_VA+0x1c L3
```

- `AddressOfFunctions` RVA (call it `AOF_RVA`)
- `AddressOfNames` RVA (call it `AON_RVA`)
- `AddressOfNameOrdinals` RVA (call it `AONO_RVA`)

Convert to VAs:

```
AOF_VA   = K32_BASE + AOF_RVA
AON_VA   = K32_BASE + AON_RVA
AONO_VA  = K32_BASE + AONO_RVA
```

---

## Step 4 — Understand the relationship between the arrays

This is the key concept. The three arrays are parallel-indexed:

```
AON_VA[i]    = RVA of the name string for the i-th named export
AONO_VA[i]   = index into AddressOfFunctions for the i-th named export
AOF_VA[AONO_VA[i]] = RVA of the function

In pseudocode, for a name search:
  for i in range(NumberOfNames):
    if names[i] == target:
      ordinal_idx = ordinals[i]
      func_rva    = functions[ordinal_idx]
      func_va     = base + func_rva
      return func_va
```

The ordinal index `AONO_VA[i]` is NOT the same as the visible ordinal number.
It is the zero-based index into `AddressOfFunctions`. The visible ordinal is
`OrdinalBase + ordinal_index`.

---

## Step 5 — Read the first few name entries

```
0:000> dd AON_VA L4                ; first 4 name RVAs
```

Follow the first:

```
0:000> da K32_BASE + poi(AON_VA)   ; first name
```

You should see an API name. Follow the second:

```
0:000> da K32_BASE + poi(AON_VA+4)
```

The names are sorted alphabetically — `AddressOfNames` is a sorted array,
which is what allows a binary search in `GetProcAddress`.

---

## Step 6 — Read the first ordinal index and function RVA

```
0:000> dw AONO_VA L4              ; first 4 ordinal indices (WORDs, not DWORDs)
```

The first value (call it `IDX_0`) is the index into `AddressOfFunctions` for
the first named export.

```
0:000> dd AOF_VA + IDX_0*4 L1     ; function RVA for first named export
```

Convert to VA:

```
0:000> ? K32_BASE + poi(AOF_VA + IDX_0*4)
```

That is the function's address in the current process. Verify it makes sense
by running `u <that address>` — you should see code, not garbage.

---

## Verify with osed-windbg

```
0:000> dx @$osed().sc.exportdir("kernel32")
```

Cross-check all fields:
- `NumberOfFunctions`, `NumberOfNames`
- `AddressOfFunctions`, `AddressOfNames`, `AddressOfNameOrdinals` RVAs

All should match your manual reads.

---

## Checkpoint

1. `NumberOfFunctions` and `NumberOfNames` — which is always larger, and why?
2. `AddressOfNames[i]` contains an RVA or a VA?
3. `AddressOfNameOrdinals` contains WORDs or DWORDs?
4. Given `AddressOfNameOrdinals[i] = 7`, what is the function's visible ordinal
   if `OrdinalBase = 1`?
5. The names in `AddressOfNames` are sorted. How does that help `GetProcAddress`?

---

## Key formula

```
function_va = base + AddressOfFunctions[AddressOfNameOrdinals[i]]
```

Where `i` is the index in `AddressOfNames` where the target name was found.
This formula is the core of all export resolution code.
