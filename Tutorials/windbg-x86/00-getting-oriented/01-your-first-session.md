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

Alternatively from a command prompt:

```bat
windbgx -o -G hello_args_x86.exe alpha beta gamma
```

`-o` tells WinDbg to handle all first-chance exceptions in the child. `-G`
tells it to pass the initial breakpoint — the process will run until it does
something interesting (or you set a breakpoint).

Without `-G` the process will pause at the loader before `main` executes.
Leave `-G` off for this exercise. You want that initial pause.

When the debugger pauses at the loader breakpoint you'll see something like:

```
(1abc.2d4): Break instruction exception - code 80000003 (first chance)
ntdll!LdrpDoDebuggerBreak+0x30:
77d4b832 cc              int     3
```

That `int 3` is the debugger's initial soft breakpoint injected by the loader.
You're inside ntdll, before main has run.

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

Now set a breakpoint on `main` and run:

```
0:000> bp hello_args_x86!main
0:000> g
```

The process runs until `main` is entered. The breakpoint fires and the debugger
pauses again. Now `eip` should be at the start of `main`.

Run `r` again. Compare the register values to what you saw at the loader
breakpoint. Notice:

- `eip` has changed dramatically — you're now in `hello_args_x86`, not ntdll.
- `esp` has also changed, because the stack has grown to accommodate the call
  to `main`.
- `ebp` has not been set up yet if you're paused *at the first instruction*
  of main (the `push ebp`). Step one instruction:

```
0:000> p
```

Step again:

```
0:000> p
```

Now `ebp` should equal what `esp` was before the `mov ebp, esp` instruction
(the standard function prologue). Verify: run `r` and confirm `ebp == esp` was
true before `sub esp, N` ran.

---

## Step 4 — Walk a function from entry to return

You're at the start of `main`. Run `u eip L20` to see the first 32 instructions
of main. Find the `ret` or `retn` at the end. Note its address.

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

## Step 5 — The console output cross-check

Let the process finish:

```
0:000> g
```

The console (if you launched from a terminal) should show:

```
argc = 4
  arg[0] = "hello_args_x86.exe" (sum=...)
  arg[1] = "alpha" (sum=...)
  arg[2] = "beta" (sum=...)
  arg[3] = "gamma" (sum=...)
done
```

If you see that output, the session worked correctly.

---

## Checkpoint

Before continuing, answer these in your notes:

1. What does `r` show you and why is it the first command you run?
2. What does `k` show you and how does it differ from just reading `eip`?
3. When the debugger pauses at the loader breakpoint, where is `eip`? In what
   module?
4. You set `bp hello_args_x86!main`. What would happen if you set
   `bp main` instead? (Hint: is `main` an unambiguous symbol?)
5. You stepped over `ret` and watched `eip` change. Describe in one sentence
   what the CPU did during that instruction.

---

## Writeup prompt

In your notes file, write a paragraph titled **"What happens between launching
a process and the first instruction of main."** Include: what the loader does,
what the initial breakpoint is, and what the call chain at that point looks
like.

If you can write it without reopening the debugger, the model has stuck.
