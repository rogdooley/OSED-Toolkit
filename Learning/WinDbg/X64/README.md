# WinDbg for OSED — x64 Companion

This is a companion to [../X86/README.md](../X86/README.md).
Read the x86 series first. This series covers only the differences.

For the full workflow guide, see [../windbg-cheatsheet.md](../windbg-cheatsheet.md).
For ARM notes, see [../ARM/README.md](../ARM/README.md).

## The three categories of x64 differences

1. **Register and calling convention changes** — 64-bit general-purpose
   registers, four register arguments (rcx, rdx, r8, r9), shadow space
2. **TEB/PEB structure offsets** — same concepts, different offsets and pointer
   widths
3. **PE32+ header format** — wider pointer fields in the Optional Header

Every osed-windbg `sc.*` command adapts automatically to the process
architecture. You do not need to pass any flag; the toolkit detects pointer
size at runtime.

## Modules

| # | Module | What changes from x86 |
|---|---|---|
| 01 | [x64 orientation](01-x64-orientation.md) | Registers, calling convention, shadow space |
| 02 | [PEB walk on x64](02-peb-walk-x64.md) | GS:0x60, wider offsets, 8-byte pointers |
| 03 | [PE exports on x64](03-exports-x64.md) | PE32+ magic, wider imagebase |

## When to use the x64 series

- Debugging a WoW64 process's 64-bit layers
- Analyzing a 64-bit target binary before OSED-style exploitation
- Understanding why your x86 shellcode running under WoW64 still accesses a
  64-bit PEB (hint: it doesn't — WoW64 maintains a separate 32-bit PEB)

## WoW64 note

A 32-bit process running under WoW64 on a 64-bit OS has **two PEBs**: a 32-bit
one (accessible via `fs:[0x30]` from the 32-bit code, at `$peb` in WinDbg)
and a 64-bit one (accessible via `gs:[0x60]` from the 64-bit thunk layer). For
OSED's 32-bit exploit scenarios, you always use the 32-bit PEB. The x64 series
covers the 64-bit PEB only.
