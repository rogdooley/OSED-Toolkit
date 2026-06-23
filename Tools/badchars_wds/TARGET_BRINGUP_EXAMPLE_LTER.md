# Target Bring-Up Example: Vulnserver LTER

This is a filled-in example of the checklist in
[`TARGET_BRINGUP_CHECKLIST.md`](/Users/dooley/Documents/GithubClone/OSED-Toolkit/Tools/badchars_wds/TARGET_BRINGUP_CHECKLIST.md).

Use it as a model for documenting a real target before trusting automation.

---

## 1. Choose the right analysis mode

### Target

- Application: `vulnserver.exe`
- Command: `LTER`
- Wire format: `LTER .` + payload + `\r\n`

### Observed behavior

When a recognizable payload was sent:

- the command path hit `vulnserver+0x1821`
- the observed command buffer preserved positions
- high bytes were transformed rather than simply truncating the copy

Example observation from the debugger:

```text
LTER . =q=q BBBB CCCC
```

where the payload had originally started with:

```text
bc f0 bc f0
```

### Mode decision

This is a **transform-preserving** target, not a raw truncation target.

Use:

- [`compare_dump.py`](/Users/dooley/Documents/GithubClone/OSED-Toolkit/Tools/badchars_wds/compare_dump.py)

Do not start with:

- [`run_badchars.py`](/Users/dooley/Documents/GithubClone/OSED-Toolkit/Tools/badchars_wds/run_badchars.py)

The iterative engine assumes raw byte-for-byte comparison and is the wrong tool
for `LTER` once you have confirmed transform behavior.

---

## 2. Pick the breakpoint

### Selected breakpoint

```text
vulnserver+0x1821
```

### Why this breakpoint was chosen

It was validated on the real `LTER` command path:

- Vulnserver started and listened on TCP/9999
- a client connected
- sending `LTER .` payloads hit `Breakpoint 0`

Observed debugger output:

```text
Breakpoint 0 hit
eip=00401821
vulnserver+0x1821:
00401821 e8a2150000      call    vulnserver+0x2dc8 (00402dc8)
```

### Why this breakpoint is good enough

At this point:

- `poi(@esp+4)` pointed at the command buffer
- the command buffer clearly contained the sent `LTER .` prefix
- the payload bytes were visible immediately after the prefix

This makes it a good **source-before-copy / parser-buffer** breakpoint for
measuring what `LTER` does to the input bytes.

---

## 3. Derive the three numbers

Read:

- [`THREE_NUMBERS.md`](/Users/dooley/Documents/GithubClone/OSED-Toolkit/Tools/badchars_wds/THREE_NUMBERS.md)

### Number 1: sender prefix length

Wire prefix:

```text
LTER .
```

Byte length:

```text
6
```

Breakdown:

- `L` = 1
- `T` = 1
- `E` = 1
- `R` = 1
- space = 1
- `.` = 1

### Number 2: payload offset

For the diagnostic `LTER` payload, the framework payload started directly with
`MAGIC`.

So:

```text
offset = 0
```

### Number 3: `dump_expr` displacement

At the breakpoint:

```text
db poi(@esp+4) L40
```

showed:

```text
4c 54 45 52 20 2e 3d 71 3d 71 42 42 42 42 43 43 ...
L  T  E  R     .  ...
```

This proves:

- `poi(@esp+4)` points at the start of `LTER .`
- payload begins 6 bytes later

Therefore:

```text
dump_expr = poi(@esp+4)+6
```

### Agreement check

For this target:

- prefix length = 6
- offset = 0
- displacement = 6

These agree:

```text
displacement = prefix_len + offset = 6 + 0 = 6
```

---

## 4. Validate one manual dump

### Sent payload

A recognizable payload was sent:

```text
LTER . + bc f0 bc f0 + BBBBCCCC + \r\n
```

### Relevant debugger output

Stack:

```text
dd @esp L10
0109f1d8  0109f1e8 00e95e58 00000000 00000000
```

Candidate pointer:

```text
db poi(@esp+4) L40
00e95e58  4c 54 45 52 20 2e 3d 71 3d 71 42 42 42 42 43 43
00e95e68  43 43 0d 0a ...
```

ASCII view:

```text
da poi(@esp+4)
"LTER .=q=qBBBBCCCC.."
```

### Interpretation

The payload starts at:

```text
poi(@esp+4)+6
```

But the bytes do **not** begin with raw `MAGIC`.

Instead of:

```text
bc f0 bc f0
```

the observed bytes were:

```text
3d 71 3d 71
```

### Result

The breakpoint and dump base are correct.

The command path is **transforming** the bytes before or during the observed
stage.

That means:

- geometry is correct
- target mode is transform-preserving
- the iterative raw-compare engine is not the correct first tool

---

## 5. Configure transport explicitly

Recommended transport config:

```json
{
  "transport": {
    "type": "tcp",
    "host": "127.0.0.1",
    "port": 9999,
    "timeout": 3.0,
    "prefix": "LTER .",
    "suffix": "\r\n",
    "read_banner": true,
    "banner_size": 4096
  }
}
```

Why not callback:

- the protocol is simple enough for explicit framing
- the prefix is operationally important and should be visible in config
- callback transport adds audit overhead for no gain here

---

## 6. Run the smallest useful validation

### Step 1: capture one aligned dump

Use the validated breakpoint and dump base:

```text
bp vulnserver+0x1821 ".echo BP_HIT; .writemem C:/dbg/dump.bin (poi(@esp+4)+6) ((poi(@esp+4)+6)+0x200); g"
```

### Step 2: analyze with transform mode

Run:

```powershell
py .\compare_dump.py --dump C:\dbg\dump.bin --magic bcf0bcf0 --exclude 00,0a,0d --table
```

Expected outcome:

- transformed bytes detected
- ASCII-only surviving charset conclusion
- preserved low-byte range
- corruption beginning at `0x80`

---

## 7. Interpret the outcome correctly

### What this target is telling you

`LTER` is not a classical “badchar until truncation” case.

It is a **charset-constrained transform** case.

The useful result is:

- which bytes survive unchanged
- which bytes are transformed
- which bytes should be excluded up front for protocol reasons

### Practical exploit-dev conclusion

Treat the target as constrained to an ASCII-safe character set.

Do not assume arbitrary shellcode bytes or arbitrary gadget addresses will
survive the path.

---

## 8. Final profile summary

### Good facts

- command path confirmed
- breakpoint confirmed
- payload pointer confirmed
- prefix length confirmed
- dump base confirmed
- transform behavior confirmed

### Final bring-up decision

Use:

- `breakpoint = vulnserver+0x1821`
- `dump_expr = poi(@esp+4)+6`
- transport prefix `LTER .`
- `compare_dump.py` for initial analysis

Do not use iterative raw comparison as the first-line tool for this command.

---

## 9. What “working” means for this target

This target profile is working when:

1. a manual dump consistently starts at the first payload byte
2. `compare_dump.py` consistently reports the same transform behavior
3. the observed surviving charset is stable across runs
4. later exploit stages use only bytes allowed by that charset

That is the correct success condition for `LTER`.
