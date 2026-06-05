# WinDbg for OSED — x86 Windows 10

A hands-on tutorial series for exploit developers studying for OSED. The
series starts from a blank WinDbg screen and ends with you manually resolving
any Windows API from first principles — the same technique your shellcode will
use during the exam.

## Why this series exists

WinDbg is not intuitive. The documentation assumes you already understand
what you need to look at; it only tells you the command syntax. The result is
students who know fifty commands but cannot answer a simple question like
"where is my recv buffer in memory right now?" without guessing.

This series teaches the opposite workflow: **start with the question, then
reach for the command.** Every exercise is structured around a question you
could not previously answer. When you finish, you'll know both the answer and
why the command that produced it is the right one.

## Modules

Work them in order. Each module assumes the previous one.

| # | Module | Skill unlocked |
|---|---|---|
| 00 | [Getting Oriented](00-getting-oriented/README.md) | Launch, attach, navigate WinDbg without getting lost |
| 01 | [Reading C Code in the Debugger](01-reading-c-code/README.md) | Map source-level concepts (local variables, function calls, pointers) to debugger output |
| 02 | [The Windows Process Model](02-windows-process-model/README.md) | Navigate TEB → PEB → Ldr by hand using only raw memory reads |
| 03 | [Walking the Module List](03-module-list-walk/README.md) | Traverse the PEB loader list and locate any module by name |
| 04 | [PE Headers and the Export Directory](04-pe-headers-and-exports/README.md) | Walk PE headers from the MZ signature to a function's virtual address |
| 05 | [Hash-Based API Resolution](05-hash-api-resolution/README.md) | Understand and verify ROR13 and other shellcode hash algorithms |

## Companion

For x64 differences — register calling convention, wider pointers, GS
segment — see [../windbg-x64/README.md](../windbg-x64/README.md). Read the
x86 series first. The x64 companion only covers deltas.

## How each exercise is structured

- **Driving question** — what you will be able to answer when done.
- **Setup** — target binary and WinDbg launch command.
- **Steps** — numbered, each ending in a checkpoint question.
- **Verification** — where applicable, a cross-check using `dx @$osed().sc.*`
  from the osed-windbg toolkit (see `osed-windbg/` at the repo root).
- **Writeup prompt** — one paragraph you write without reopening the debugger.

If you can write the paragraph cold, the exercise has stuck.

## What you need

- Windows 10 x86 VM (or x64 with WoW64)
- WinDbg Preview (windbgx) — free from the Microsoft Store
- The osed-windbg toolkit loaded: `.scriptload <path>\osed-windbg\dist\osed.js`
- Visual C++ Build Tools for the `src/` targets
- No Immunity Debugger, no Mona.py, no IDA yet

## What you should already know

- What a register is and how to read a hexadecimal number
- The difference between `mov eax, 5` and `mov eax, [5]`
- What a stack frame is in general terms (push/pop, esp/ebp)
- How to open a terminal on Windows

That is all. The series builds every other concept from scratch.
