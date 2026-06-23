# Breakpoint Selection

This note is for picking a breakpoint that produces a trustworthy dump.

Most badchar automation failures are not caused by Python or `cdb`. They are
caused by breaking at the wrong place:

- too early, before the bytes are where you think they are
- too late, after the buffer is partially consumed or corrupted
- on the wrong routine entirely

The rule is simple:

> Break where the buffer you want to dump is stable, then dump immediately.

---

## The two valid breakpoint styles

There are only two patterns worth using.

### 1. Source-before-copy breakpoint

Break at the call site, just before the vulnerable copy or transform routine is
invoked.

Use this when:

- the command buffer already contains the bytes you want to inspect
- the destination buffer is not yet trustworthy
- the target transforms input before crashing
- you are validating protocol framing or prefix handling

Typical signs:

- `poi(@esp+4)` or another argument points at:
  - `TRUN /.:/[payload]`
  - `LTER .[payload]`
  - `USER [payload]`

Good for:

- Vulnserver `LTER`
- parser-local source buffers
- one-shot manual geometry validation

### 2. Destination-after-copy breakpoint

Break after the copy has completed, usually at the `ret` of a small wrapper or
at a point where the destination pointer is already valid and the bytes are in
place.

Use this when:

- you want the copied destination buffer
- the copy completes cleanly
- the destination pointer is stable in a register or stack slot

Typical signs:

- `@eax` points at the destination after a `strcpy`-style call
- the destination buffer contains `[A * offset][MAGIC]...`

Good for:

- lab targets
- persistent services
- raw-copy targets where source framing is irrelevant

---

## What not to do

### Do not break at function entry and dump the destination

At entry, the copy has not happened yet.

If you dump the destination there, you will often read:

- zeros
- stale bytes
- partially initialized memory

### Do not step inside the breakpoint command list

Avoid breakpoint bodies like:

```text
pt; gu; .writemem ...
```

That mixes control-flow assumptions into the dump path and makes failures hard
to reason about.

Preferred rule:

- pick a breakpoint where the buffer is already right
- dump immediately
- `g`

### Do not assume libc routines are always the right anchor

`msvcrt!strcpy` is useful only if the command path actually reaches it.

If the target instead:

- normalizes bytes
- copies through a helper
- uses parser-local transforms

then the libc breakpoint will either never hit or show the wrong buffer.

---

## How to find the breakpoint

### Strategy A: start with the obvious copy routines

For classic stack overflows:

```text
bp msvcrt!strcpy
bp msvcrt!strncpy
bp msvcrt!memcpy
bp msvcrt!sprintf
g
```

Send a recognizable payload and inspect the arguments.

If one breakpoint hits and the relevant pointer shows your bytes, you have a
working anchor.

### Strategy B: use the target-local call site

If you already know the vulnerable handler from IDA or prior debugging, break
on the target-local offset:

```text
bp vulnserver+0x1821
g
```

Then inspect the candidate arguments:

```text
dd @esp L10
db poi(@esp+4) L40
db poi(@esp+8) L40
db poi(@esp+c) L40
```

This is often better than chasing standard library routines because it gives
you the exact parser/handler state for that command.

### Strategy C: follow the pointer, not the symbol name

If you are unsure which argument is the real buffer, use a recognizable payload
and look for:

- protocol prefix bytes
- `MAGIC`
- the candidate bytearray

The correct breakpoint is the one where at least one candidate pointer clearly
shows the buffer you intend to analyze.

---

## Deciding between source and destination

Choose based on what question you are answering.

### If you want to know whether the protocol/parser mangled the bytes

Break on the source side.

Examples:

- `LTER` includes protocol framing and applies transforms
- command-local normalization is the thing you are measuring

Then your dump base is usually:

```text
poi(@esp+4) + prefix_len + offset
```

### If you want to know whether the final copied bytes survive in the target buffer

Break on the destination side.

Examples:

- raw `strcpy` path
- wrapper function returns with `dst` in `@eax`

Then your dump base is usually:

```text
@eax + offset
```

---

## Manual breakpoint validation

Before automating, validate the breakpoint with one small payload.

Use:

- protocol prefix
- `MAGIC`
- a few obvious trailing bytes

Example:

```text
LTER . bc f0 bc f0 42 42 42 42 43 43 43 43
```

At the breakpoint, inspect likely pointers until you can answer:

1. Which pointer holds the bytes I care about?
2. Does that pointer start with protocol framing or with payload?
3. Where does `bc f0 bc f0` actually begin?

If you cannot answer those three questions from one breakpoint hit, the
breakpoint is not good enough yet.

---

## Failure diagnosis

### Breakpoint never hits

Likely causes:

- wrong command path
- wrong module offset
- target does not reach that routine
- listener/service never reached the processing path

### Breakpoint hits but pointer does not contain your payload

Likely causes:

- wrong routine
- wrong argument
- breakpoint too early
- breakpoint on a helper unrelated to the vulnerable buffer

### Breakpoint hits and dump exists, but `MAGIC` is wrong

Likely causes:

- breakpoint is okay
- dump base is wrong

That is now a three-number problem, not a breakpoint problem.

---

## Fast checklist

A breakpoint is good if:

1. it hits on the exact command path you care about
2. at least one inspected pointer visibly contains your payload
3. you can derive a dump base that starts at `MAGIC`
4. you can dump once and verify `dump[:4] == bcf0bcf0`

If any one of those is false, keep debugging the breakpoint manually. Do not
run automation yet.
