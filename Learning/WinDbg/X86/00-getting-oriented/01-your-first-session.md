# Exercise 01 — Your First Session

## The question

You launch a process under WinDbg and it pauses at a breakpoint. Without
looking at any reference: what are the first five things you check, and what
command do you use for each?

Write your answer before reading on. It does not matter if you're wrong — it
matters that you've committed an answer you can compare against.

---

## Setup

Build `src/hello_args.c` for x86:

```bat
cl /nologo /Od /Zi /MT /W3 hello_args.c /link /OUT:hello_args_x86.exe
```

## Step 1 — Launch under WinDbg

Open WinDbg Preview. File → Launch Executable. Pick `hello_args_x86.exe` and
set the arguments to `alpha beta gamma`.

Alternatively from a command prompt (no `-G` flag):

```bat
windbgx -o hello_args_x86.exe alpha beta gamma
```

`-o` tells WinDbg to attach to and debug child processes. Do **not** add `-G`
here — `-G` would silently pass through the initial breakpoints we want to
observe.

### What you will see on Windows 10: two breaks, not one

On Windows 10, launching a console application spawns a **conhost.exe**
helper process first. WinDbg fires its first initial break *inside conhost*,
before hello_args.exe has even started. You will see something like:

```
ModLoad: 00a20000 00a8d000   hello_args_x86.exe
ModLoad: 77630000 777cf000   ntdll.dll
...
(1c08.d94): Break instruction exception - code 80000003 (first chance)
...
ntdll!LdrpDoDebuggerBreak+0x2b:
776fdb6b cc              int     3
1:001>
```

The `1:001>` prompt means **process 1, thread 1** — that is the conhost
process, not your target. hello_args_x86.exe modules are already listed in
`ModLoad` output, but the *target process* has not yet received its own
initial break.

At this first pause:
- You **cannot** set `bp hello_args_x86!main` yet and expect it to fire —
  the module is shown in `ModLoad` lines but is not yet executing; the
  breakpoint will go deferred and may not resolve in this process context.
- Run `lm` here anyway and observe the module list — it reflects the loader's
  initial state, not the running process yet.

### Getting to the target process

Run `g` to continue past this first (conhost) break:

```
1:001> g
```

WinDbg runs, finishes loading DLLs, then pauses again at the **second**
initial break — this time inside hello_args_x86.exe's own main thread:

```
(1c08.d94): Break instruction exception - code 80000003 (first chance)
...
ntdll!LdrpDoDebuggerBreak+0x2b:
776fdb6b cc              int     3
0:000>
```

The prompt is now `0:000>` — **process 0, thread 0** — your target. `eip` is
still inside ntdll (both breaks call the same `LdrpDoDebuggerBreak` function).
This is expected and correct. You are now paused at the moment after all DLLs
have loaded but before `main` has executed.

**This is the initial pause the exercise is about. Do the five-things check
from Step 2 here, at the `0:000>` prompt.**

---

## Step 2 — Read the five things

**Register state.** Run:

```
0:000> r
```

Look at `eip`, `esp`, `ebp`, and `eax`. Note where `eip` points — it should
be inside `ntdll` somewhere. The exact value doesn't matter yet; what matters
is that you can read the output and point at each register.

**The call chain.** Run:

```
0:000> k
```

You'll see several frames. At a loader breakpoint this won't be a call chain
you recognize. That's fine. Note how many frames there are.

**Disassembly forward from eip.** Run:

```
0:000> u eip L10
```

`L10` means "show 16 (0x10) instructions." You're looking at the instructions
starting from the current instruction pointer. The first one should be the
`int 3` (opcode `cc`) you saw in the break message.

**Stack contents.** Run:

```
0:000> dd esp L10
```

Sixteen DWORDs from the top of the stack. Look at the first value — that is
the return address that the current function will return to when it's done.

**Loaded modules.** Run:

```
0:000> lm
```

You'll see ntdll, kernel32, and a few others. Note the base address of ntdll
(leftmost column). You'll use this later to understand if an address is "in"
a module.

---

## Step 3 — Break on main

You are now at the `0:000>` prompt (the hello_args process, main thread).
The module is loaded and symbols are available. Set a breakpoint on `main`:

```
0:000> bp hello_args_x86!main
```

WinDbg should confirm with `Breakpoint 0 set at hello_args_x86!main`. If it
says "deferred" and the module was not yet listed in `lm`, re-run `lm` to
confirm the module loaded — if it hasn't, you may still be at the first
(conhost) break. Run `g` once more to get to the second break (`0:000>`)
and then set the BP.

Now run `g` — **not** `p`:

```
0:000> g
```

`g` runs until a breakpoint fires. `p` steps one instruction. **Do not
press `p` here.** If you step with `p` from the ntdll break, you will walk
through ntdll's `LdrpDoDebuggerBreak` function instruction by instruction.
You will still be in ntdll after 10 `p`s. Use `g` to run to the breakpoint.

---

### Verify you are at main before continuing

The `main` breakpoint fires. **Before doing anything else**, confirm `eip`
is inside `hello_args_x86` and not ntdll:

```
0:000> r eip
```

The address must fall inside the `hello_args_x86` range shown by `lm`:

```
0:000> lm m hello_args_x86
start    end      module name
00a20000 00a8d000   hello_args_x86
```

If `eip` is inside `00a20000–00a8d000`: **you are at main. Continue.**

If `eip` is still in `77xxxxxx` (ntdll range): the breakpoint did not fire.
Two likely causes:
- The BP went deferred (you set it at the `1:001>` conhost break).
  Fix: `bl` to list breakpoints. If it shows `d` (deferred), clear it with
  `bc 0`, get to the `0:000>` process break, and set it again.
- You pressed `p` instead of `g`. Fix: `g` to run, or restart and try again.

---

Once `eip` is confirmed inside `hello_args_x86`, disassemble the prologue:

```
0:000> u eip L5
```

You should see the classic MSVC prologue as the first three instructions:

```
hello_args_x86!main:
00a21040 55              push    ebp
00a21041 8bec            mov     ebp,esp
00a21043 81ecNNNNNNNN    sub     esp,NNNh
```

**`ebp` has not been set up yet** — you are paused before `push ebp` has
executed. Record the current `esp` value from `r`. Then step through
**three times**:

```
0:000> p    ; executes: push ebp   (saves caller's ebp; esp -= 4)
0:000> p    ; executes: mov ebp,esp (ebp = current esp; frame is anchored)
0:000> p    ; executes: sub esp,N  (reserves local variable space)
```

After the third `p`, run `r` and verify:

- `ebp` equals `esp` + 4 (the value esp had right before `push ebp`, minus 4
  for the push itself — i.e., the value esp had when you entered main, minus 4)
- `esp` equals `ebp - N` (locals reserved below the frame pointer)

Expressed as arithmetic WinDbg can check:

```
0:000> ? ebp - esp        ; should equal the NNN from the sub esp instruction
```

This three-instruction sequence — `push ebp`, `mov ebp,esp`, `sub esp,N` —
is the **standard MSVC function prologue**. You will see it at the start of
every non-inlined function in every target you debug. Recognizing it at a
glance is a prerequisite for reading stripped binaries.

---

## Step 4 — Walk a function from entry to return

You are now three instructions into `main` — past the prologue, at the
first instruction of the function body. Run:

```
0:000> u eip L20
```

This shows the next 32 instructions of `main` starting from your current
position. Scan through to the end of the output. Find the `ret` or `retn`
instruction — it should be near the bottom. Note its address.

Set a breakpoint there:

```
0:000> bp <address-of-ret>
0:000> g
```

The process runs `main` to completion. When the breakpoint fires at the `ret`,
look at `[esp]` — that's the return address `main` is about to use:

```
0:000> dd esp L1
```

Write down that address. Now step over the `ret`:

```
0:000> p
```

Verify: `eip` should now equal the address you noted. You've watched a function
return. This is the mechanism that exploitation hijacks.

---

## Step 5 — Let the process run to completion

Let the process finish:

```
0:000> g
```

WinDbg will show `ntdll!NtTerminateProcess` or a similar exit message and
the prompt will become inactive (the process is gone).

### Where is the console output?

When **windbgx** launches the child process, the child's stdout goes to
WinDbg's internal output pane — **not** back to the terminal you launched
windbgx from. The PowerShell/cmd window that started windbgx will not
show `argc = 4 ...`.

To verify the program produces the correct output, run it once **standalone**
(outside the debugger) directly from your terminal:

```powershell
.\hello_args_x86.exe alpha beta gamma
```

Expected output:

```
argc = 4
  arg[0] = "hello_args_x86.exe" (sum=...)
  arg[1] = "alpha" (sum=98)
  arg[2] = "beta" (sum=100)
  arg[3] = "gamma" (sum=106)
done
```

If you see that, the binary is correct. The debugging session itself is the
real verification — if your breakpoints fired, `eip` moved into
`hello_args_x86`, and `r` showed the values you expected, the session worked.

### A note on `-G`

The command-line shortcut `windbgx -o -G hello_args_x86.exe ...` adds the
`-G` flag which silently passes all initial breakpoints (including the
conhost and process loader breaks from Step 1). This is useful once you
know what those breaks look like and want to skip straight to your own
breakpoints. For this tutorial module, omit `-G` so you see the initial
breaks. Later exercises will note when `-G` is the right choice.

---

## Checkpoint

Before continuing, answer these in your notes:

1. What does `r` show you and why is it the first command you run?
2. What does `k` show you and how does it differ from just reading `eip`?
3. On Windows 10 with a console app, why does WinDbg fire an initial break
   at `1:001>` before reaching the target process at `0:000>`?
4. You set `bp hello_args_x86!main`. What would happen if you set
   `bp main` instead? (Hint: is `main` an unambiguous symbol when multiple
   modules each have a `main`?)
5. You stepped over `ret` and watched `eip` change. Describe in one sentence
   what the CPU did during that instruction.
6. Why does `bp hello_args_x86!main` go **deferred** if you set it while
   still at the `1:001>` (conhost) break?

---

## Writeup prompt

In your notes file, write a paragraph titled **"What happens between launching
a process and the first instruction of main."** Include: what the loader does,
why there are two initial breaks on Windows 10 with a console app, what the
call chain looks like at the second break, and how `bp` deferred vs resolved
behaves.

If you can write it without reopening the debugger, the model has stuck.
