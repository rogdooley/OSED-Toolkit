# WinDbg for OSED - ARM Notes

This is a separate companion document for ARM and ARM64 targets. It is not a
replacement for the x86 workflow guide; it exists so architecture-specific
differences do not dilute the main exploitation flow.

## What belongs here

- Register and calling convention differences for ARM and ARM64
- Pointer-width and structure-offset differences
- Stack layout and frame-pointer conventions that differ from x86
- Any WinDbg commands whose meaning changes materially on ARM targets

## What does not belong here

- The full x86 OSED workflow
- PE walking material that is identical across architectures
- Generic debugger commands that do not change on ARM

## Suggested use

Treat this as a delta sheet. Read the main workflow guide first:
[../windbg-cheatsheet.md](../windbg-cheatsheet.md)

Then use this document only when an ARM-specific register, calling convention,
or structure offset becomes relevant.
