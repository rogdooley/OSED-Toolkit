# Module 03 — Walking the Module List

## What this module teaches

How to traverse the PEB module list entry by entry, comparing `BaseDllName`
against a target string, and extracting the `DllBase` when found. By the end
you will be able to manually locate any loaded DLL by name — without `lm`,
without any WinDbg symbol knowledge, using only memory reads.

This is the manual equivalent of what your shellcode will do at runtime.

## Why this module exists

Module 02 taught you the structure. This module teaches you the algorithm.
The distinction matters: knowing the structure means you understand what to
read; knowing the algorithm means you know when to stop and what to return.

The common OSED bug in PEB-walking shellcode is getting the termination
condition wrong (infinite loop or crash), or using the wrong offsets when
switching between the three module list types. This module forces both issues
into the open by making you do it by hand.

## The exercises

| # | Exercise | What you'll be able to do after |
|---|---|---|
| 01 | [The linked-list walk](01-the-linked-list.md) | Step through all entries in a circular LIST_ENTRY list |
| 02 | [LDR_DATA_TABLE_ENTRY fields](02-ldr-data-table-entry.md) | Read DllBase and BaseDllName for any entry |
| 03 | [Finding kernel32](03-finding-kernel32.md) | Locate kernel32 by name comparison — exactly as shellcode does |
| 04 | [Verify with osed-windbg](04-verify-with-osed.md) | Cross-check your manual walk against `dx @$osed().sc.modules()` |

Total time: 2–3 hours.

## What you need

- Any x86 process under WinDbg
- osed-windbg toolkit loaded
- Module 02 completed (offsets memorized or in your cheat sheet)
