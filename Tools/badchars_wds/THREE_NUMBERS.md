# Finding The Three Numbers

This note is the shortest practical guide for configuring a new target in
`badchars_wds`.

If the tool misbehaves, the first assumption should be that one of these three
numbers is wrong:

1. the **sender prefix length**
2. the **payload offset**
3. the **`dump_expr` displacement**

These three values must agree. Most failures are not debugger bugs. They are
geometry bugs.

---

## The three numbers

### 1. Sender prefix length

This is the number of bytes your sender places in front of the framework
payload on the wire.

Examples:

- `TRUN /.:/` = 8 bytes
- `LTER .` = 6 bytes
- no protocol prefix = 0 bytes

This matters only when your breakpoint dumps a **source buffer** that still
contains the command prefix.

If `poi(@esp+4)` points at:

```text
LTER .[MAGIC][candidates]...
```

then the correct dump base is:

```text
poi(@esp+4)+6
```

### 2. Payload offset

This is the `orchestrator.offset` value.

It is the count of filler bytes placed before `MAGIC` inside the framework
payload:

```text
[A * offset][MAGIC][candidates][padding]
```

Examples:

- `offset = 0`
  - `MAGIC` starts at the first byte of the framework payload
- `offset = 2006`
  - the first 2006 bytes are filler, then `MAGIC`

This matters when your breakpoint dumps a **destination buffer** after the copy
has completed.

If `@eax` points at the start of the destination buffer and your payload layout
is:

```text
[A * 2006][MAGIC]...
```

then the correct dump base is:

```text
@eax+0x7d6
```

because `2006 decimal = 0x7d6`.

### 3. `dump_expr` displacement

This is the number inside `stage.dump_expr` that moves the dump base from the
buffer start to the first byte of `MAGIC`.

Examples:

- `poi(@esp+4)`                -> no displacement
- `poi(@esp+4)+6`              -> skip command prefix
- `@eax+0x7d6`                 -> skip 2006 bytes of filler

This is not an independent number. It must be derived from either:

- the sender prefix length, or
- the payload offset

depending on which buffer you are dumping.

---

## The one rule

`dump_expr` must evaluate to the address of the **first byte of `MAGIC`**.

If it does not, the rest of the run is noise.

The framework assumes:

```text
dump[0:4] == bcf0bcf0
```

If that is false, stop and fix the geometry first.

---

## How to derive the numbers

### Case A: dumping the source buffer

Use this when the breakpoint is at or just before the copy call, and the source
buffer still contains the protocol framing.

Layout:

```text
[protocol prefix][framework payload]
```

Framework payload:

```text
[A * offset][MAGIC][candidates][padding]
```

Then:

```text
dump displacement = prefix_len + offset
```

Examples:

- `TRUN /.:/` + payload, `offset = 0`
  - `dump_expr = poi(@esp+4)+8`
- `LTER .` + payload, `offset = 0`
  - `dump_expr = poi(@esp+4)+6`
- `USER ` + payload, `offset = 2006`
  - `dump_expr = poi(@esp+4)+0x7db`
  - because `5 + 2006 = 2011 = 0x7db`

### Case B: dumping the destination buffer

Use this when the breakpoint is after the copy has completed and the dumped
buffer does not include protocol framing.

Layout:

```text
[A * offset][MAGIC][candidates][padding]
```

Then:

```text
dump displacement = offset
```

Examples:

- destination starts at `@eax`, `offset = 0`
  - `dump_expr = @eax`
- destination starts at `@eax`, `offset = 2006`
  - `dump_expr = @eax+0x7d6`

---

## How to verify manually

Before trusting automation, do one manual run and check whether the dump begins
with `MAGIC`.

### Step 1: set the breakpoint

Set a breakpoint at a location where the relevant buffer is stable.

Two valid patterns:

- **source-before-copy**
  - dump the source argument
- **destination-after-copy**
  - dump the destination after the copy is done

Do not single-step inside the breakpoint command list. Dump immediately from a
known-stable location.

### Step 2: inspect the candidate pointer

At the breakpoint, inspect the bytes directly:

```text
db poi(@esp+4) L40
db poi(@esp+4)+6 L20
db @eax L40
db @eax+0x7d6 L20
```

You are looking for:

```text
bc f0 bc f0
```

The first location where those four bytes appear is the correct dump base.

### Step 3: test the exact dump

Once you think the base is correct, dump it once:

```text
.writemem C:/dbg/dump.bin <dump_expr> (<dump_expr>)+0x200
```

Then verify:

```python
with open(r"C:\dbg\dump.bin", "rb") as handle:
    data = handle.read()
print(data[:4].hex())
```

Expected:

```text
bcf0bcf0
```

If that value is wrong:

- wrong prefix length
- wrong offset
- wrong dump displacement
- or wrong breakpoint

Do not run automation until this passes.

---

## Failure diagnosis

### Symptom: `timeout` / dump not found

Usually means:

- breakpoint never hit
- or the breakpoint command did not complete

This is not a three-number problem yet.

### Symptom: `invalid_dump` / magic mismatch

Usually means one of the three numbers is wrong.

Check:

- did you include the protocol prefix in the source buffer?
- did you add the payload offset when dumping a source buffer?
- did you accidentally use decimal in `dump_expr` where WinDbg expected hex?

### Symptom: clean pass on a target that should not clean-pass

Usually means:

- the dump base is wrong
- or you are on a transformed path like `LTER`

Check the first 32 dumped bytes manually.

### Symptom: every high byte looks bad on `LTER`

That is expected behavior for a transformed target, not a normal truncating
badchar case. Use `compare_dump.py`, not the iterative workflow.

---

## Common mistakes

### Mistake 1: forgetting the protocol prefix

You dump `poi(@esp+4)` and compare it to a payload that starts with `MAGIC`,
but the actual buffer starts with:

```text
LTER .[MAGIC]...
```

Fix:

```text
dump_expr = poi(@esp+4)+6
```

### Mistake 2: using the payload offset against the source buffer only

If your sender prepends bytes and your payload also has filler, both count:

```text
dump displacement = prefix_len + offset
```

### Mistake 3: forgetting WinDbg numeric rules

In `dump_expr`, write:

- `+0x7d6`, not `+2006`

unless you explicitly use decimal notation:

- `+0n2006`

### Mistake 4: breaking before the buffer is stable

If the copy has not happened yet and you dump the destination, you will read
zeros or stale data.

If the source is already transformed and you expected raw bytes, you are on the
wrong path for a raw-copy comparison.

---

## Fast checklist

Before any automated run:

1. What exact bytes does the sender prepend?
2. How many filler bytes are before `MAGIC`?
3. Does `dump_expr` skip both of those when necessary?
4. Does a manual dump start with `bcf0bcf0`?

If the answer to 4 is no, stop and fix the geometry.

That is the entire discipline.
