# Exercise 04 — Verify with osed-windbg

## Purpose

Review all the sc.* commands that relate to PE parsing and export resolution.
Practice using them for rapid verification during exploit development.

---

## The relevant commands

| Command | What it does |
|---|---|
| `dx @$osed().sc.pe("mod")` | PE headers: base, DOS, NT, machine, entrypoint, export dir RVA |
| `dx @$osed().sc.exportdir("mod")` | Export directory fields: NumberOfFunctions/Names, array RVAs |
| `dx @$osed().sc.exports("mod")` | All named exports with ordinal, RVA, VA |
| `dx @$osed().sc.export("mod","name")` | Single export with full walk details |
| `dx @$osed().sc.exportwalk("mod","name")` | Step-by-step walk (use this for debugging) |
| `dx @$osed().sc.exportat("mod", idx)` | Export by ordinal index |

---

## Step 1 — PE header sanity check on a target module

Pick any module from your exploit development lab (essfunc.dll if you have
vulnserver running, or use kernel32 or ntdll):

```
0:000> dx @$osed().sc.pe("kernel32")
```

Verify the `ExportDir RVA` matches what you read manually in Exercise 01.

---

## Step 2 — Enumerate exports for a filtered list

```
0:000> dx @$osed().sc.exports("kernel32", "Virtual")
```

The second argument filters by substring. This shows all `Virtual*` exports —
`VirtualAlloc`, `VirtualFree`, `VirtualProtect`, etc. These are the functions
you will commonly need in DEP-bypass ROP chains.

Note their addresses. These addresses change on every reboot (ASLR). The
toolchain resolves them at runtime — which is the whole point of PEB walking.

---

## Step 3 — exportwalk for a ROP target

During an actual OSED exploit you will typically need to confirm the address
of `VirtualProtect` or `VirtualAlloc`:

```
0:000> dx @$osed().sc.exportwalk("kernel32", "VirtualProtect")
```

Read through every step. Confirm the steps match the algorithm from Exercise 03.

---

## Step 4 — exportat for ordinal-only exports

Some functions are exported by ordinal only (no name). Look them up by index:

```
0:000> dx @$osed().sc.exportat("kernel32", 0)
```

Ordinal index 0 (visible ordinal = `OrdinalBase + 0 = 1`) may or may not have
a name. Browse through several indices and observe which ones are named and
which aren't.

---

## Step 5 — IAT verification (for understanding loader behavior)

The Import Address Table shows the actual runtime addresses of all functions
a binary has linked against. After the loader runs, the IAT is populated:

```
0:000> dx @$osed().sc.iat()
```

For each entry, the `Target` column is the function's current VA. The
`Symbol+Offset` column shows the nearest named export (which should be
`+0x0` if the slot points at the function start).

This is how you verify that a call in your target binary lands where you think
it does. If the `Status` column shows `outside-module` or `non-exec`, something
unusual is happening (e.g., a trampolined import, a hooking tool, or corrupt
IAT).

---

## Step 6 — Run the full verification sequence

On a fresh process (restart your lab target if needed), run through all five
levels of the resolution chain without notes:

1. `dx @$osed().sc.peb()` → confirm PEB and Ldr addresses
2. `dx @$osed().sc.base("kernel32")` → confirm kernel32 base
3. `dx @$osed().sc.pe("kernel32")` → confirm export dir RVA
4. `dx @$osed().sc.exportdir("kernel32")` → confirm NumberOfNames, array RVAs
5. `dx @$osed().sc.exportwalk("kernel32", "LoadLibraryA")` → confirm full walk

Write down the `LoadLibraryA` address. You will use it in Module 05.

---

## Checkpoint

1. What is the difference between `sc.export` and `sc.exportwalk`?
2. Why do the function VAs change between reboots on a system with ASLR?
3. A function's IAT entry shows `Status: outside-module`. What could cause this?
4. What does `sc.exports("kernel32", "Virtual")` return that `sc.export` cannot?
5. Name the three critical VAs an OSED DEP-bypass shellcode typically needs
   from kernel32.
