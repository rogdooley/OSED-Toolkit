# Exercise 02 — Following Function Calls

## The question

When a function calls another function, how does the argument data travel
across the call? How do you tell, from disassembly alone, what was passed?

---

## Setup

```
windbgx -o stack_lab_x86.exe HelloWorld
```

Break on `run_and_print`:

```
0:000> bp stack_lab_x86!run_and_print
0:000> g
```

---

## Step 1 — Read the call site before stepping in

You're at the entry of `run_and_print`. Disassemble the whole function:

```
0:000> uf eip
```

Scan for the `call stack_lab_x86!process_buffer` instruction. The instructions
before it prepare the arguments. On x86 cdecl, arguments are pushed right to
left (last argument first). So if `process_buffer(input)` takes one explicit
argument, you'll see one `push` before the `call`.

Note the address of the `call` instruction. Call it `CALL_SITE`.

**Predict before you look:** What will `[esp]` hold at the moment
`process_buffer`'s first instruction executes? (Hint: the `call` instruction
pushes the return address first, then the CPU jumps.)

---

## Step 2 — Break exactly at the call and read the pre-call stack

```
0:000> bp CALL_SITE
0:000> g
```

You're now paused *at* the `call` instruction, before it has executed. The
arguments have been pushed but the return address has not (the `call` does
that atomically when it executes).

Read the stack:

```
0:000> dd esp L6
```

The top value(s) should be the argument(s). The first argument to
`process_buffer` (the `input` pointer) will be at `[esp]` because it was
pushed last (cdecl pushes right-to-left, and with one arg, that is just one
push at `[esp]`).

Plus the hidden return-value pointer you found in Exercise 01. If it's there,
what slot is it at?

Follow the pointer at `[esp]` or `[esp+4]` (whichever is `input`):

```
0:000> db poi(esp) L20       ; or poi(esp+4) — match what you found above
```

You should see `HelloWorld`.

---

## Step 3 — Step into the call and confirm the frame shift

Step one instruction (into `process_buffer`):

```
0:000> p
```

Run `r` to confirm `eip` is at the start of `process_buffer`. Now run:

```
0:000> dd esp L1
```

`[esp]` is now the **return address** — the instruction in `run_and_print`
after the `call`. The arguments have moved: they are now at `[esp+4]`,
`[esp+8]`, etc.

**After `push ebp` + `mov ebp, esp` runs (step through the prologue):**

- `[ebp+0x00]` = saved `ebp` of `run_and_print`
- `[ebp+0x04]` = return address (back into `run_and_print`)
- `[ebp+0x08]` = first argument to `process_buffer`

Verify each of these with `dd`:

```
0:000> dd ebp L4
```

---

## Step 4 — Trace the argument chain end to end

You should now be able to state, for any given instruction in
`process_buffer`, where the original user input (`argv[1]`) came from:

```
main → run_and_print (passed as argv[1])
run_and_print → process_buffer (passed as input)
process_buffer → uses it as source for strncpy
```

Set a breakpoint at the `call strncpy` site inside `process_buffer`:

```
0:000> bp <addr-of-call-strncpy>
0:000> g
```

When it fires, the `input` pointer is still on the stack (it's a local of
`process_buffer` or an argument). Find it and confirm the value matches what
you set as `argv[1]`.

---

## Step 5 — Walk out: step over the call and watch eip return

Step over the `strncpy` call with `p`. Watch `eip`. It moves from `strncpy`
back to the instruction in `process_buffer` after the `call`. The saved return
address was popped off the stack by the `ret` inside `strncpy`.

Run `k`. The call chain no longer shows `strncpy` — it has returned.

Now step over the rest of `process_buffer` until its `ret`. Use `p` or set a
breakpoint on the `ret` instruction. When `ret` fires:

```
0:000> dd esp L1
```

That single DWORD is about to become `eip`. Step:

```
0:000> p
0:000> r eip
```

Confirm `eip` is back in `run_and_print`, at the instruction after the
original `call process_buffer`.

---

## Step 6 — The call convention proof

The x86 cdecl calling convention says: the **caller** cleans up the stack
after the call (adds N*4 to `esp` to discard the pushed arguments). The
callee does not.

After `process_buffer` returns to `run_and_print`, look for the `add esp, N`
or `pop` instruction(s) that follow the call:

```
0:000> u eip L4
```

If you see `add esp, 8` (or similar), that is the caller discarding the
two arguments it pushed. The number should be `4 * number-of-visible-args`
(not counting the hidden return-value pointer — compilers sometimes handle
that differently).

Note the exact instruction and what `N` is.

---

## Checkpoint

Answer in your notes:

1. On x86 cdecl, in what order are arguments pushed onto the stack (left to
   right or right to left)?
2. When `call func` executes, what does the CPU push and where does it jump?
3. Inside a callee, what is `[ebp+0x08]`?
4. Who discards the arguments after a cdecl call returns: caller or callee?
5. Draw the stack from just before `call process_buffer` fires through to just
   after `process_buffer`'s prologue completes. Show three stack states.

---

## Writeup prompt

Write a paragraph titled **"How arguments move across a function call on x86."**
Cover: push order, what `call` does to `esp`, what the callee's prologue does,
and who cleans up. Do not look at these notes while writing.
