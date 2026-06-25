# Exercise 04 — Verify with osed-windbg

## Purpose

Every manual walk you have done in this module has a one-command shortcut via
the osed-windbg toolkit. This exercise verifies your manual results against the
toolkit output and shows you when the toolkit is faster than manual work — and
when manual work is still required.

---

## Prerequisites

The osed-windbg script loaded:

```
0:000> .scriptload C:\path\to\osed-windbg\dist\osed.js
```

Verify it loaded:

```
0:000> dx @$osed().help()
```

You should see the command table.

---

## Step 1 — PEB summary

```
0:000> dx @$osed().sc.peb()
```

This reads the same fields you walked manually: PEB address, Ldr pointer,
ImageBase, BeingDebugged, ProcessParameters.

Compare each field against what you recorded in your Module 02 notes.

---

## Step 2 — Module list

```
0:000> dx @$osed().sc.modules()
```

This walks `InLoadOrderModuleList` and returns every entry with Base, End,
Size, Name, and Path. Your manual walk from Exercise 01–03 should have
produced the same names in the same order.

Count the entries. The toolkit reports the full list in one command.

---

## Step 3 — Find kernel32 base

```
0:000> dx @$osed().sc.base("kernel32")
```

This should match the `DllBase` you extracted manually in Exercise 03. If it
doesn't, find the discrepancy — either your manual read was wrong or there is
something unusual about the process's module list.

---

## Step 4 — When the toolkit is NOT enough

The toolkit hides the intermediate steps. You cannot use it to:

- Debug a PEB-walking shellcode that is producing the wrong answer
- Understand why a particular DLL is or isn't in the list
- Verify that your shellcode is reading the right field with the right offset

Those scenarios require the manual approach you just practiced. The toolkit is
a verification shortcut for when you already know the answer and want to
confirm it, or when you need a quick read during exploit development. The
manual approach is what you use when something is wrong.

---

## Step 5 — Iterate both approaches on a fresh target

Attach to any other process on your VM (notepad.exe, calc.exe, etc.) and:

1. Manually walk the module list to find `ntdll.dll` and its base.
2. Verify with `dx @$osed().sc.base("ntdll")`.
3. Manual walk to find the last entry in the list.
4. Verify the count with `dx @$osed().sc.modules()`.

If you can do the manual walk on an unfamiliar process without looking up the
offsets, this module is complete.

---

## Checkpoint

1. What command lists all loaded modules via osed-windbg?
2. What command returns the base address of a specific module?
3. Name one scenario where the toolkit is insufficient and you must walk
   the list manually.
4. What does `dx @$osed().sc.peb()` output that you could not get from
   `!peb`? (Hint: think about what field the toolkit explicitly reads.)
