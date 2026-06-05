# Exercise 01 — Local Variables and the Stack Frame

## The question

Given a function's disassembly (no source, no symbols), what is its stack
frame layout, and where do each of its local variables live?

---

## Setup

```
windbgx -o stack_lab_x86.exe HelloWorld
```

Break on `process_buffer`:

```
0:000> bp stack_lab_x86!process_buffer
0:000> g
```

---

## Step 1 — Read the prologue

When the breakpoint fires, `eip` is at the first instruction of
`process_buffer`. Run:

```
0:000> u eip L8
```

You should see something like:

```
stack_lab_x86!process_buffer:
00401060 55              push    ebp
00401061 8bec            mov     ebp,esp
00401063 81ec98000000    sub     esp,98h
...
```

This is the **standard function prologue**. Every MSVC-compiled function
without optimization starts this way.

**Decode it:**

1. `push ebp` — saves the caller's frame pointer. The caller's `ebp` is now
   at `[new_ebp + 0]`, i.e., `[ebp + 0x00]` after step 2.
2. `mov ebp, esp` — establishes the frame pointer. From now on, `ebp` is
   the anchor for this frame: locals are at negative offsets, arguments at
   positive offsets.
3. `sub esp, 0x98` — reserves space for local variables. `0x98` bytes = 152
   bytes of locals.

**Draw the frame layout on paper before stepping further:**

```
higher addresses (callers)
|
|  [ebp + 0x08]   first argument to process_buffer
|  [ebp + 0x04]   saved return address
|  [ebp + 0x00]   saved ebp (caller's frame pointer)  <-- ebp points here
|  [ebp - 0x04]   local 1
|  [ebp - 0x08]   local 2
|  ...
|  [ebp - 0x98]   bottom of local frame  <-- esp points here
|
lower addresses (stack grows down)
```

---

## Step 2 — Verify the layout with `r` and arithmetic

Run:

```
0:000> r ebp
0:000> r esp
0:000> ? ebp - esp
```

The last command does arithmetic. The result should be `0x98` (152 decimal),
matching the `sub esp, 0x98` you saw. If it's not exactly `0x98` it's because
the prologue hasn't finished — step past it first with `p` until `eip` is past
the `sub esp`.

Now read the slot that holds the saved return address:

```
0:000> dd ebp+4 L1
```

That value should match the return address you see in `k` for frame 00
(`process_buffer`'s caller).

And the argument:

```
0:000> dd ebp+8 L1
```

Follow that pointer with `db`:

```
0:000> db poi(ebp+8) L20
```

You should see `HelloWorld` in ASCII. That is the `input` parameter.

---

## Step 3 — Find the local buffer in disassembly

Run `uf stack_lab_x86!process_buffer` to see the whole function. Find the
instruction that calls `strncpy`. It will look like:

```
push  <size>          ; third arg: max bytes
push  <pointer>       ; second arg: source (input)
lea   eax, [ebp-NNN]  ; first arg: &local_copy
push  eax
call  _strncpy
```

The `lea eax, [ebp-NNN]` tells you the exact offset of `local_copy` from
`ebp`. Note that offset.

**Verify before stepping:**

```
0:000> ? ebp - NNN         ; compute the absolute address of local_copy
0:000> db <that-address> L10   ; look at the uninitialized stack memory
```

You should see garbage (uninitialized stack bytes). Now step until `strncpy`
returns (use `bp` on the instruction after the `call strncpy` and `g`, or
step with `p` — your choice).

After `strncpy` returns:

```
0:000> db <address-of-local_copy> L20
```

You should now see `HelloWorld` in ASCII — the buffer has been filled.

---

## Step 4 — Identify all locals from the disassembly alone

Still in `uf` output: scan for every `[ebp-N]` and `[ebp+N]` reference.
Build a table:

| Offset | Access type | What it likely is |
|---|---|---|
| `[ebp+0x04]` | RetAddr | saved return address |
| `[ebp+0x08]` | argument | `input` pointer |
| `[ebp-0x04]` | write/read | `len` (int) |
| `[ebp-0x08]` | write/read | `stats.length` or similar |
| `[ebp-NNN]` | `lea` target | `local_copy[128]` |

(The exact offsets on your build may differ from the above. Fill in what you
actually see.)

**Key rule:** When you see `lea reg, [ebp-NNN]`, a buffer starts there.
When you see `mov [ebp-N], reg` or `mov reg, [ebp-N]`, a scalar lives there.
Buffer locals always have `lea` addressing. Scalars have `mov`.

---

## Step 5 — The struct return value

`process_buffer` returns a `BufferStats` struct by value. On x86 MSVC, a
struct return value larger than 8 bytes is passed as a hidden first argument:
the caller allocates space on its own stack and passes a pointer to
`process_buffer` as an invisible first arg. The function writes the result
there and returns the pointer in `eax`.

Check: look at the arguments in `uf`. Does the argument count match what you
expect from source? If `process_buffer` has only one explicit source argument
but the disassembly pushes two things before the call, the second is the
hidden return-value pointer.

Find it in the caller (`run_and_print`):

```
0:000> uf stack_lab_x86!run_and_print
```

Look for the `lea reg, [ebp-NNN]` + `push reg` that happens before
`call process_buffer`. That `[ebp-NNN]` is where `run_and_print` has
allocated the `BufferStats` struct on its own stack.

---

## Checkpoint

Answer in your notes:

1. What is the purpose of `push ebp` + `mov ebp, esp` at a function entry?
2. Given `sub esp, 0x40`, how much stack space has been reserved for locals?
3. You see `lea eax, [ebp-0x8c]`. What is `[ebp-0x8c]`?
4. You see `mov eax, [ebp-0x04]`. What is this accessing?
5. Where is the return address in a stack frame relative to `ebp`?
6. How does MSVC pass a large struct return value from a function?

---

## Writeup prompt

Draw `process_buffer`'s stack frame on paper (to scale — actual offsets from
your debugger session). Label every slot you can identify. Hand this to a peer
who has also done this exercise. If they can read it without explanation, you
got it right.
