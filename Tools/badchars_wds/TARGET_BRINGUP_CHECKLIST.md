# Target Bring-Up Checklist

Use this when pointing `badchars_wds` at a target you have not configured
before.

The goal is not to get lucky once. The goal is to get to a point where one
manual check tells you whether the config is right.

---

## 1. Choose the right analysis mode

There are two target classes.

### Truncating / early-stop targets

Use:

- [run_badchars.py](/Users/dooley/Documents/GithubClone/OSED-Toolkit/Tools/badchars_wds/run_badchars.py)

Examples:

- `strcpy`-style null truncation
- command handlers where one byte ends the copy

Expected workflow:

- iterative exclusions
- one newly confirmed bad byte per iteration

### Transform-preserving targets

Use:

- [compare_dump.py](/Users/dooley/Documents/GithubClone/OSED-Toolkit/Tools/badchars_wds/compare_dump.py)

Examples:

- `LTER` ASCII folding
- parser paths where positions are preserved but bytes are remapped

Expected workflow:

- one aligned dump
- full positional comparison
- charset conclusion

If you choose the wrong mode, the tool output will mislead you.

---

## 2. Pick the breakpoint

Read:

- [BREAKPOINT_SELECTION.md](/Users/dooley/Documents/GithubClone/OSED-Toolkit/Tools/badchars_wds/BREAKPOINT_SELECTION.md)

Your breakpoint must satisfy all of these:

1. it hits on the command path you are testing
2. a visible pointer at the breakpoint contains your payload
3. that buffer is stable enough to dump immediately

If the breakpoint does not satisfy those, stop there.

---

## 3. Derive the three numbers

Read:

- [THREE_NUMBERS.md](/Users/dooley/Documents/GithubClone/OSED-Toolkit/Tools/badchars_wds/THREE_NUMBERS.md)

You need these values:

1. sender prefix length
2. payload offset
3. `dump_expr` displacement

These must agree.

If they do not agree, the automation is meaningless.

---

## 4. Validate one manual dump

Before running any automation, do exactly one manual check.

### Send a small recognizable payload

Use something like:

```text
[prefix] bc f0 bc f0 42 42 42 42 43 43 43 43
```

### Inspect the candidate pointer

At the breakpoint, inspect likely pointers:

```text
dd @esp L10
db poi(@esp+4) L40
db poi(@esp+8) L40
db poi(@esp+c) L40
db @eax L40
```

### Dump from the exact base you believe is correct

```text
.writemem C:/dbg/dump.bin <dump_expr> (<dump_expr>)+0x200
```

### Verify the first four bytes

```python
with open(r"C:\dbg\dump.bin", "rb") as handle:
    data = handle.read()
print(data[:4].hex())
```

Required result:

```text
bcf0bcf0
```

If that fails, do not run automation.

---

## 5. Configure transport explicitly

Prefer explicit built-in transport settings when possible:

- `type = tcp`
- `prefix = "..."`
- `suffix = "\r\n"`
- `read_banner = true/false`

Use callback transport only when the protocol genuinely requires logic beyond:

- connect
- optional banner read
- prefix + payload + suffix

Opaque senders make target bring-up harder.

---

## 6. Run the smallest useful validation

### For truncating targets

Run:

```powershell
py .\validate_cdb.py --config .\config.target.json
```

You want:

- breakpoint command sent
- breakpoint listed
- breakpoint hit
- dump written

Then run:

```powershell
py .\run_badchars.py --config .\config.target.json -v
```

### For transform targets

Capture one aligned dump, then run:

```powershell
py .\compare_dump.py --dump C:\dbg\dump.bin --magic bcf0bcf0 --exclude 00,0a,0d --table
```

You want a stable transform/charset conclusion, not an iterative badchar loop.

---

## 7. Interpret the outcome correctly

### `Outcome: CLEAN`

Meaning:

- the tool observed exactly what it expected

For a real target, this is only trustworthy if the manual magic check already
passed.

### `Outcome: FAILED status=invalid_dump`

Meaning:

- geometry problem
- wrong three numbers
- or wrong breakpoint/dump base

### `Outcome: FAILED status=timeout`

Meaning:

- breakpoint never hit
- target did not reach the expected path
- or no dump was produced

### `Outcome: exhausted`

Meaning:

- the iterative engine kept learning bad bytes until `max_iterations`
- usually fine for synthetic or highly constrained targets

---

## 8. Know when to stop

Stop and re-evaluate if:

1. the manual dump does not begin with `MAGIC`
2. the breakpoint hits, but no pointer clearly contains your payload
3. the target transforms bytes but you are still using the iterative engine
4. you are changing breakpoint, sender, and `dump_expr` all at once

One controlled change at a time.

---

## 9. Definition of “working”

A target profile is working when:

1. you can explain the breakpoint choice
2. you can explain the three numbers
3. one manual dump starts with `bcf0bcf0`
4. the selected tool mode matches the target behavior
5. the automated result matches the manual evidence

That is the bar.
