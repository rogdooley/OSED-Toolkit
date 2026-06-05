# Module 04 — PE Headers and the Export Directory

## What this module teaches

How to walk a PE (Portable Executable) file's headers from the `MZ` signature
at the module base all the way to a specific exported function's virtual
address. By the end you will be able to take any DLL's base address and find
any named export without using symbols, `x`, or any WinDbg knowledge of
function addresses.

This is the second half of shellcode API resolution. Module 03 found the
module base. This module finds the function within the module.

## Why this module exists

Every time you call `GetProcAddress` in a Windows program, it does exactly
this walk internally. Every shellcode that resolves APIs manually does this walk
too. If you do not understand it, you cannot write it from scratch or debug it
when it produces the wrong answer.

## The exercises

| # | Exercise | What you'll be able to do after |
|---|---|---|
| 01 | [DOS and NT headers](01-dos-and-nt-headers.md) | Read `e_lfanew`, find the NT header, verify the PE signature |
| 02 | [The Export Directory](02-export-directory.md) | Locate and parse `IMAGE_EXPORT_DIRECTORY` |
| 03 | [Resolving a function by name](03-resolving-a-function.md) | Walk AddressOfNames → AddressOfNameOrdinals → AddressOfFunctions |
| 04 | [Verify with osed-windbg](04-verify-with-osed.md) | Cross-check with `dx @$osed().sc.exportwalk()` and `.sc.export()` |

Total time: 3–5 hours.

## What you need

- A 32-bit process that has kernel32.dll loaded (all of them do)
- osed-windbg toolkit loaded
- Module 03 completed (you can already locate kernel32's base address)

## Reference

The full PE format documentation is in `Documentation/Windows/PEFormat/`. The
exercises in this module are walk-throughs, not reference reading. If you want
the complete field listing, read the PEFormat docs afterward.
