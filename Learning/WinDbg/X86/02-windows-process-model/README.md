# Module 02 — The Windows Process Model

## What this module teaches

How to navigate from the CPU's FS segment register to the Process Environment
Block (PEB) and all the way to the list of loaded DLLs — using only raw memory
reads. By the end you will be able to look up any module's base address without
running `lm` or asking WinDbg anything about modules.

This is the prerequisite for writing position-independent shellcode. Every
shellcode that calls a Windows API does exactly this navigation at runtime.

## Why this module exists

The TEB → PEB → Ldr chain is the first thing a shellcode executes. If you
cannot walk it manually in the debugger, you cannot debug the shellcode that
does it — you're just watching bytes run and hoping.

This module teaches you the chain from the read direction. Module 03 takes
you through the module list itself. Module 04 then walks the PE export table.
Taken together, the three modules reproduce every step of shellcode API
resolution, manually, in the debugger.

## The exercises

| # | Exercise | What you'll be able to do after |
|---|---|---|
| 01 | [The TEB](01-the-teb.md) | Read TEB fields by offset using `fs:[0x30]` and raw `dd` |
| 02 | [The PEB](02-the-peb.md) | Read PEB fields including the Ldr pointer |
| 03 | [Ldr structures](03-ldr-structures.md) | Navigate `PEB_LDR_DATA` and its three module lists |

Total time: 2–4 hours.

## What you need

- Any debuggable process (the `stack_lab_x86.exe` from Module 01 works fine)
- WinDbg Preview with the osed-windbg toolkit loaded
- Public symbols for ntdll (WinDbg auto-downloads these)

## What you should already know

- Modules 00 and 01 completed
- `poi()`, `dd`, `db`, `dt` commands
- The concept of a pointer chain

## A note on symbols

This module uses `dt ntdll!_TEB`, `dt ntdll!_PEB`, etc. These commands require
public symbols for ntdll. WinDbg Preview downloads them automatically on first
use if you have internet access. The `dt` output gives you ground truth for the
offsets you will then read manually.

For every field you look at with `dt`, this module also shows you how to read
the same value manually with `dd`. The goal is that after this module, you no
longer need `dt` — you have the offsets memorized (or in your cheat sheet).
