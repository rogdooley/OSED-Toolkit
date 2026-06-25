# Exercise 03 — Reading functions without symbols

The exercise that addresses the `dv` failure directly. Vulnserver, like most
real targets, has no private symbols. You cannot ask the debugger "what are
the local variables?" — it doesn't know. You have to infer the frame layout
from the disassembly itself.

This is not a workaround. This is the actual skill.

## The question

Given a function in a stripped binary, derive its complete stack frame
layout — including all local variables, the destination buffer of any unsafe
copy, and the location of saved `ebp` and saved return address — using only
the disassembly.

## Why this question

Three reasons.

First, on the OSED exam you will be given binaries without symbols. If you
can only read functions when symbols hand you the layout, you cannot pass.

Second, even when symbols are available, they often lie or are incomplete.
Stripped optimized code has variables that the compiler merged, eliminated,
or moved between stack and registers. The disassembly is the truth; symbols
are a comment on it.

Third, reading prologues fluently makes you 5x faster at every other
exercise. You stop guessing offsets. You read them off the page.

## What you need to recognize

### The classic prologue

```
push ebp                ; save caller's frame pointer
mov  ebp, esp           ; establish ours
sub  esp, 0x208         ; allocate 0x208 bytes of locals
```

After these three instructions, the frame looks like:

```
ebp + 0x08 ... argument 2 (and beyond)
ebp + 0x04 ... saved return address
ebp + 0x00 ... saved ebp  (ebp itself points here)
ebp - 0x04 ... first dword of locals
ebp - 0x08 ... second dword of locals
...
ebp - 0x208 ... last byte of allocated locals
esp        ... = ebp - 0x208 right after the prologue
```

Every reference of the form `[ebp - N]` for `0 < N <= 0x208` is a local.
Every reference of the form `[ebp + N]` for `N >= 8` is an argument.

### Identifying the receive buffer

Look for the call to `recv`:

```
push <flags>
push <len>
push <buffer_addr>      ; <-- third pushed
push <sock>             ; <-- fourth pushed (pushes in reverse order)
call ws2_32!recv
```

The third push from the top (i.e. the first push you see when reading
top-down) is the flags. Wait — let me be careful. `recv(sock, buf, len, flags)`.
Args push right-to-left in cdecl, so:

```
push flags    ; arg 4
push len      ; arg 3
push buf      ; arg 2
push sock     ; arg 1
call recv
```

The `buf` argument is one of those four pushes. It's almost always computed
as `lea reg, [ebp - N]` just before being pushed, where `N` is the offset
of the buffer in locals.

### Identifying the destination of an unsafe copy

For `strcpy(dst, src)`:

```
push <src>
push <dst>
call strcpy
```

The first push is the destination. It's almost always a `lea reg, [ebp - N]`
for some `N`. That `N` is the buffer offset.

For `memcpy(dst, src, n)`:

```
push <n>
push <src>
push <dst>
call memcpy
```

Similar pattern.

### The epilogue

```
mov esp, ebp     ; or:  add esp, 0x208
pop ebp
ret              ; or:  ret <bytes-to-clean-up>
```

`ret` pops the saved return address into `eip`. `ret 0x10` does the same
then adds `0x10` to `esp` (stdcall cleanup of 4 arguments). The presence of
`ret <N>` tells you the calling convention.

## The exercise

You will derive the frame layout for three functions in vulnserver. For each
one, before looking at it in the debugger, predict in your notes how big you
expect the local area to be, and how many arguments you expect.

### Function A — F_trun (the TRUN handler)

You found this in Exercise 02. Use the entry address you noted.

```
0:000> uf <F_trun_entry>
```

(`uf` disassembles the whole function. If the binary has enough metadata,
this just works. If `uf` complains, use `u <entry> L40` and read instruction
by instruction.)

Answer in your notes:

1. What is the value of `sub esp, ?` in the prologue?
2. List every `[ebp - N]` reference in the function. For each, what's `N`?
3. Where is the destination buffer of the strcpy? (i.e. what's the `N` in
   `lea eax, [ebp - N]` immediately before the `push eax` for the strcpy
   destination?)
4. How many arguments does this function take? (Look at `[ebp + 8]`,
   `[ebp + 0xc]`, etc. references, and check the `ret` for cleanup bytes.)

### Function B — The connection handler (F_recv_handler)

You found this in Exercise 02 as well — the function that contains the
`call recv` and dispatches on commands.

```
0:000> uf <F_recv_handler_entry>
```

Answer:

1. How big is the local area?
2. Where in the locals is the receive buffer? (Look for the `lea reg,
   [ebp - N]` immediately before the `push` for `recv`'s second argument.)
3. How does this function decide which command handler to call? (Look for
   `cmp` / `strncmp` patterns. Don't list every one — describe the
   structure.)
4. How does the function handle a closed connection? (Look for branches off
   the `recv` return value.)

### Function C — Pick any other command handler

`F_stats`, `F_rtim`, `F_ltim`, `F_hmon`, `F_gter`, `F_gmon`, `F_gdog`, etc.
Any one. Find it the same way you found `F_trun`: send a payload starting
with the command name, break on the dispatch, follow the `call` it makes.

Derive its frame layout. Compare to `F_trun`. **What's different about
TRUN?** Specifically, what does TRUN do that the others don't? Why is TRUN
the vulnerable one?

If the answer is "TRUN does an unbounded strcpy and the others use bounded
copies," verify it by finding the `strncpy` or equivalent in the safe
handler.

## The model update

Before this exercise, you used the debugger to *find* offsets. After it,
you can compute offsets by reading the program. The debugger becomes a
verification tool, not a source of truth.

This is also when you stop being scared of stripped binaries. They look
intimidating until you realize the prologue tells you everything. After 10
functions, your eye snaps to `sub esp, N` and you know the layout without
counting.

## Writeup

In your notes, write a 1-page document titled *"How to read a stack frame
without symbols."* It should include:

- The canonical prologue and what each instruction does to the frame
- How to identify locals vs arguments by their `[ebp +/- N]` offset
- How to find the destination of an unsafe copy from the disassembly alone
- A worked example using F_trun: the prologue, the buffer location, the
  strcpy destination, the frame size

The writeup is the deliverable. Make it good enough that you'd hand it to
another student.

## Common mistakes

- **Forgetting cdecl pushes are right-to-left.** The *last* push before a
  call is the *first* argument. Read backward.
- **Confusing the buffer's start with its end.** `lea reg, [ebp - 0x208]`
  points at the *start* of the buffer. The buffer extends from there toward
  higher addresses for whatever its size is.
- **Assuming `sub esp, N` means "buffer is N bytes."** It means "locals
  area is N bytes." The buffer is a subset of that area. Other locals also
  live there.
- **Missing the second prologue instruction.** Some compilers emit
  `enter 0x208, 0` instead of `push ebp; mov ebp, esp; sub esp, 0x208`.
  Same effect, different bytes. Don't be fooled.
- **Reading `[esp + N]` as if it were `[ebp + N]`.** Once the function
  manipulates `esp` (e.g. for pushes), `[esp]` is no longer the bottom of
  locals. Stick to `[ebp +/- N]` for frame analysis.

## What this unlocks

You can now read any function in a stripped Windows binary and derive its
frame layout. That makes you self-sufficient. Module 02 (offset derivation,
EIP control strategies, return address selection) builds directly on this.

You will use this skill every working day of every exploit you ever write.
