# Module 01 — Reading C Code in the Debugger

## What this module teaches

How to map source-level C concepts — local variables, function arguments,
pointers, and structs — to what you observe in WinDbg. By the end you will be
able to look at a function's disassembly without symbols and answer: what is
the stack frame layout, what does each local variable hold right now, and
where did this function's input come from?

## Why this module exists

Most debugging in OSED-style exploit work happens against binaries that have
no symbols and no source. But those binaries were compiled from C. The compiler
produced predictable patterns that you can learn to read in reverse. Once you
can look at a prologue and epilogue and reconstruct the approximate stack frame
layout, stripped binaries stop being opaque.

This module teaches you that pattern using a target you *can* see the source
for, so you can verify your reading against ground truth.

## The exercises

| # | Exercise | What you'll be able to do after |
|---|---|---|
| 01 | [Local variables and the frame](01-local-variables-and-the-frame.md) | Read a function's prologue and draw its stack frame layout |
| 02 | [Following function calls](02-following-function-calls.md) | Step into and out of calls, trace arguments through a call chain |
| 03 | [Pointers and dereferences](03-pointers-and-dereferences.md) | Follow a pointer chain by hand and in the debugger |

Total time: 3–5 hours.

## What you need

- `stack_lab.exe` built from `src/stack_lab.c`
- WinDbg Preview

Build (x86, Developer Command Prompt):

```bat
cl /nologo /Od /Zi /MT /W3 stack_lab.c /link /OUT:stack_lab_x86.exe
```

## What you should already know

- Module 00 completed (five essential commands)
- `push`/`pop` grow/shrink the stack toward lower addresses
- `call` pushes the return address, `ret` pops it into `eip`

## Session startup pattern (applies to every exercise in this module)

On Windows 10, launching a console app with `windbgx -o` fires an initial
break in the **conhost** helper process first (`1:001>` prompt). The target
module is not yet executing. **Always do this at the start of each session:**

```
; You see the conhost break:
1:001> g

; Now you are at the hello_args / stack_lab process break:
0:000> bp <target>!<function>    ← set your breakpoint here
0:000> g
```

If you set a breakpoint at `1:001>` it will show `deferred` and never fire.
If you accidentally step with `p` instead of running `g`, you will walk
through ntdll instructions instead of reaching your breakpoint. Each exercise
setup section assumes you are already at the `0:000>` prompt.
