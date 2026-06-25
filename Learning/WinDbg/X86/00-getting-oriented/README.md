# Module 00 — Getting Oriented

## What this module teaches

How to start a WinDbg session without immediately feeling lost. By the end
you will be able to launch a process under the debugger, hit a breakpoint,
inspect the five things that matter at any pause, and navigate the disassembly
forward and backward from where you stopped.

This module uses the smallest possible target: a 10-line C program that prints
its arguments and exits. The goal is zero distraction from the tooling itself.

## Why this module exists

The biggest source of early WinDbg confusion is not the commands — it is the
feedback loop. You type a command, the output appears, and you don't know
whether what you see is what you expected. You can't tell correct from wrong
output because you have no model of what correct looks like.

The fix is to build the model first on a target so simple you already know
what should happen. Then when the output is unexpected, you'll notice.

## The exercises

| # | Exercise | What you'll be able to do after |
|---|---|---|
| 01 | [Your first session](01-your-first-session.md) | Launch a process, hit a breakpoint, read the five things |
| 02 | [Five essential commands](02-five-essential-commands.md) | Use `r`, `k`, `u`, `db`/`dd`, and `lm` correctly on purpose |

Total time: 1–2 hours.

## What you need

- `hello_args.exe` built from `src/hello_args.c`
- WinDbg Preview (`windbgx`)

Build command (x86, from a Visual Studio Developer Command Prompt):

```bat
cl /nologo /Od /Zi /MT /W3 hello_args.c /link /OUT:hello_args_x86.exe
```

## What you should already know

- What EIP, ESP, and EBP are (even vaguely)
- How to open a terminal on Windows
