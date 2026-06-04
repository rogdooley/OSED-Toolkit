# Exercise 01 — The mental model

This is the only exercise in the curriculum that doesn't involve the debugger.
It's a thinking exercise. Without the conceptual scaffolding here, the next
exercises won't stick.

## The question

When you stop a program in WinDbg and stare at the screen, what are the five
things you need to be able to see in your head — independent of any specific
command?

Write your answer before you read further. Three minutes, on paper or in a
notes file. If you can't list five, list the ones you can.

---

## The five things

### 1. The stack frame

For any given function, you should be able to draw on paper:

```
higher addresses
 |
 |   ...caller's frame...
 |   argument 2          [ebp + 0x0c]
 |   argument 1          [ebp + 0x08]
 |   return address      [ebp + 0x04]   <-- writing here = control eip
 |   saved ebp           [ebp + 0x00]   <-- writing here = control ebp
 |   local variable 1    [ebp - 0x04]
 |   local variable 2    [ebp - 0x08]
 |   ...
 |   buffer              [ebp - 0xNNN]  <-- typically the overflow target
 |   esp ->
 |
lower addresses
```

The stack grows toward lower addresses on x86. `push` decrements `esp`. `pop`
increments it. A function's prologue establishes `ebp` at a known offset from
its locals so that the function can reference them at fixed `[ebp - N]`
offsets even as `esp` moves around.

If you cannot draw this for an arbitrary function before looking at the
debugger, every overflow exercise will feel like magic. It is not magic.

### 2. The call chain

When you see a stack trace:

```
00 ...   ws2_32!recv
01 ...   vulnserver+0x1958
02 ...   KERNEL32!BaseThreadInitThunk
03 ...   ntdll!__RtlUserThreadStart
```

each row is a function that is currently *paused* waiting for the row above it
to return. The chain is glued together by return addresses. Frame 01's "return
address" (`vulnserver+0x1958`) is the instruction in `vulnserver` that will
run when `recv` returns. It's literally the instruction *after* the `call
recv` inside vulnserver.

That means if you disassemble backward from `vulnserver+0x1958` with `ub`,
you'll find the `call ws2_32!recv` that's currently in flight. And the function
containing that `call` is the function that received the packet. You just
found vulnserver's connection handler without knowing anything about it.

This is the single most important insight in this module. Call stacks are not
just for "what crashed." They are for *finding interesting code without
knowing where to look.*

### 3. Memory ownership

The same address can mean very different things depending on what it points to:

- An address inside `ntdll` or `kernel32` is in a DLL's `.text` section.
  That's code. You can't usually write there. You *can* use it as a return
  target if it doesn't have ASLR.
- An address in the `0x0012xxxx` or `0x008fxxxx` range is usually stack.
  That's where saved return addresses and local buffers live. It's writable
  and reading from it is your data.
- An address in `0x00400000` (or the binary's image base) is the target
  process's own `.text`. Same as a DLL — code, not data, usually no ASLR
  unless explicitly enabled.
- An address from `0x00100000` to ~`0x7fffffff` is somewhere in user-mode
  memory. The heap, more DLLs, mapped files. Each region has its own
  permissions.

`lm` lists modules and their ranges. `!address <addr>` tells you what region
an address belongs to and what permissions it has. You will use these
constantly.

When you build a ROP chain or pick a return address, you are picking a
specific byte in a specific region. The region matters. Knowing the difference
between "this is in vulnserver" and "this is in essfunc.dll" decides whether
your exploit survives a reboot.

### 4. Control flow at the instruction level

For the function you're currently attacking, you should be able to identify:

- **Entry**: where does control arrive?
- **Input acquisition**: where does user-supplied data enter this function?
  (Usually as an argument from a caller, or read directly via `recv`/`fgets`/
  `ReadFile`.)
- **The dangerous operation**: which instruction copies that data into a
  fixed-size buffer? (`call strcpy`, `rep movsb`, a manual loop.)
- **Exit**: where does the function return?
- **The smashing path**: in between input acquisition and exit, what
  instructions could the attacker influence the operands of?

You don't need to understand every instruction. You need to find these five
landmarks. Most functions have all five within 30 lines of assembly.

### 5. The boundary between data and code

This is the boundary that exploitation crosses. The CPU executes whatever
bytes are at `eip`. Normally those bytes were placed there by the loader from
the program's `.text` section. Exploitation is the art of making the CPU
execute bytes that *you* placed in memory — typically by overflowing a buffer
on the stack, overwriting a saved return address, and pointing it at bytes
you also wrote.

For this to work, three things must be true:
- You can write your bytes into memory the program holds.
- You can make `eip` point at your bytes.
- The memory holding your bytes has execute permission.

When DEP is off, all three are usually trivial. When DEP is on, the third
condition becomes the central problem — and the answer is ROP, which is the
art of making the CPU execute *existing* code in a sequence you choose.

Until you can keep all three conditions in mind simultaneously while
debugging, exploitation will feel like a series of unrelated tricks. Once you
can, every technique you'll learn (SEH overwrite, egghunters, ROP, encoders)
becomes a variation on the same theme.

---

## The model update

Before this exercise, you may have known WinDbg commands. After it, you
should be able to describe what you're trying to *see* when you use them.

- `k` exists to read the call chain.
- `dd esp` exists to read the current stack frame.
- `u eip` exists to read control flow forward from where you are.
- `ub` exists to read it backward.
- `lm` and `!address` exist to read memory ownership.
- `r` exists to read register state and infer what the next instruction will do.

Each command is a probe into one of the five things above. If you find
yourself running commands without knowing which of the five you're probing,
you're command-typing, not debugging.

---

## Writeup prompt

Open [../notes-template.md](../notes-template.md). Write a 1-page document in
your own words titled *"What I look at when I open a debugger."* List the five
things and one example WinDbg command you'd use to probe each.

If you can't do this without re-reading the lesson, do the lesson again.
