# Module 01 — Foundations

## What this module teaches

How to read a running program in WinDbg and build a mental model of what it is
doing. By the end you will be able to take an unfamiliar Windows binary, attach
the debugger, and answer fundamental questions about its memory layout, control
flow, and data flow without needing source code or symbols.

This is the foundation. Every later module assumes you can do everything here.

## Why this module exists

The reason most students struggle in OSED is not that they lack commands. It is
that they cannot **read what the debugger is showing them**. They see a stack
trace and don't know what each frame represents. They see `ebp-0x208` and don't
know what's stored there. They see disassembly and can't tell the buffer from
the saved return address.

Until you can do those things reliably, every exploit you write is cargo cult.
You're following a recipe instead of solving a problem. That's the difference
between someone who passes OSED in 24 hours and someone who runs out of time at
hour 47.

## The exercises

Work them in order.

| # | Exercise | What you'll be able to do after |
|---|---|---|
| 01 | [The mental model](01-the-mental-model.md) | Describe the five things you need to see in your head when debugging any program. |
| 02 | [Tracing input through Vulnserver](02-tracing-input.md) | Follow a byte from `recv()` to crash, naming every function in between. |
| 03 | [Reading functions without symbols](03-reading-stripped-functions.md) | Derive a function's stack frame layout from its disassembly alone. |
| 04 | [Deriving the overflow offset](04-deriving-the-offset.md) | Calculate the exact offset to EIP from first principles, then verify with Mona. |

Total time: roughly 6–10 hours of honest work spread across 3–4 sessions.

## What you should already know

- What a stack is, in general terms
- What a register is
- The difference between `mov eax, 5` and `mov eax, [5]`
- How to launch cdb on a target and hit a breakpoint

If any of those are shaky, the [Vulnserver TRUN tracing exercise](02-tracing-input.md)
will surface that fast. That's the right order — you don't need to read every
assembly reference cover-to-cover first.

## What you do NOT need yet

- Mona.py
- Immunity Debugger
- IDA Pro or Ghidra
- The shellcoding/encoding skill
- Knowledge of SEH, DEP, ASLR

All of those come in later modules. Module 01 is just the debugger and the binary.
