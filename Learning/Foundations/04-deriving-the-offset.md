# Exercise 04 — Deriving the overflow offset

The capstone of Module 01. You've traced the data path, you've read the
frame layout. Now put it together to derive the exact offset to EIP control
without using Mona or any pattern-generation tool. Then verify with Mona.

## The question

For three different vulnerable Windows targets, derive the exact byte
offset from the start of attacker-controlled input to the saved return
address — using only the debugger and your understanding of stack frames.

Then verify your answer with `!mona pattern_create` / `!mona findmsp`. If
your answer is right, you've internalized the model. If it's wrong, you've
found a gap.

## Why this question

`!mona pattern_create` is a great tool. It is also a crutch. Students who
only ever find offsets with `pattern_create` never learn what the offset
actually *is*. They know "send pattern, read EIP, ask Mona." They don't
know why that works.

On the OSED exam, the target binaries are unfamiliar, the constraints are
nonobvious, and Mona may not even be in your environment depending on the
target. If you understand offset derivation from first principles, you can
adapt instantly when something doesn't fit the recipe.

This exercise forces you to do both: compute the offset, then check
yourself. It is the difference between "I can run Mona" and "I understand
what Mona is automating."

## The general formula

For a function `F` with frame layout:

```
ebp + 0x04   saved return address     <-- target
ebp + 0x00   saved ebp
ebp - 0x04   first local
...
ebp - BUF    start of overflow buffer
```

If the user-controlled data starts at `ebp - BUF` and grows toward higher
addresses (which it does, because `strcpy` writes forward), then:

```
OFFSET_TO_SAVED_EBP = BUF
OFFSET_TO_EIP       = BUF + 4
```

That's the whole formula. The hard part is knowing what `BUF` is — and
that comes from Exercise 03.

Two complications worth knowing:

1. **Prefix bytes.** If a protocol requires a prefix like `TRUN /.:/`
   before the overflowable content, those bytes are *part* of the source
   buffer but get copied into the destination too. In some bugs the prefix
   sits inside the destination, taking up space; in others the prefix is
   stripped before the copy. Read the disassembly to know which.

   For Vulnserver TRUN, the entire `TRUN /.:/...` string is copied verbatim.
   So OFFSET_TO_EIP from the *start of the network packet* is `BUF + 4`,
   counting the prefix.

2. **The frame may have extra bytes between the buffer and saved ebp.**
   If the compiler put another local variable at `[ebp - 4]` and the buffer
   at `[ebp - 0x208]`, then the buffer is 0x204 bytes long (it ends at
   `ebp - 0x04`, where the next local starts). Don't assume the buffer
   ends right at `ebp + 0`.

   In practice: from the *start* of the buffer at `ebp - BUF`, you need
   `BUF` bytes to fill it, then 4 more for saved ebp, then 4 more for the
   return address. So OFFSET_TO_EIP = `BUF + 4` if there's nothing between
   the buffer's end and saved ebp, or `BUF + 4 + intermediate_padding`
   otherwise.

## Target 1 — Vulnserver TRUN

You already have everything you need.

### Step 1 — Derive the offset

From Exercise 03, you have `BUF` for `F_trun`. Compute:

```
OFFSET_TO_EIP = BUF + 4
```

Write the answer in your notes *before* verifying.

### Step 2 — Verify with a marker payload

```python
import socket
PREFIX  = b"TRUN /.:/"
OFFSET  = <your computed value>
filler  = b"A" * (OFFSET - len(PREFIX))
marker  = b"BBBB"
tail    = b"C" * 100

s = socket.create_connection(("vulnserver_ip", 9999))
s.recv(1024)
s.sendall(PREFIX + filler + marker + tail + b"\r\n")
s.close()
```

Crash and check:

```
0:000> r eip
```

If `eip = 0x42424242`, your offset is right.
If not, the BBBB landed at the wrong place. You can locate them:

```
0:000> s -b 0 L?80000000 42 42 42 42
```

That searches all memory for the bytes `42 42 42 42`. You'll see your
marker somewhere on the stack. Compute how far off you were.

### Step 3 — Verify with Mona

Now do the same crash with a cyclic pattern:

```python
# In Immunity or with mona standalone:
# !mona pattern_create 5000

# Send that exact pattern instead of A*OFFSET + BBBB + C*tail
```

When it crashes, take the value of EIP and ask Mona:

```
!mona findmsp -distance 5000
```

Or in cdb without mona, use the equivalent from `msf-pattern_offset`:

```
msf-pattern_offset -q <eip_value>
```

Compare to the offset you derived. They should match. If they don't,
investigate which is wrong — your derivation or your reading of the
disassembly.

## Target 2 — A second Vulnserver command

Pick a *second* vulnerable command from vulnserver. Check the source if you
need to — vulnserver is open-source and there are multiple vulnerable
commands beyond TRUN (e.g. GMON, KSTET, GTER, HTER, LTER). Some take input
in different ways.

For your chosen command:

1. Find its handler (Exercise 02 technique — break on dispatch, follow the
   call).
2. Derive its frame layout (Exercise 03 technique — read the prologue).
3. Identify the unsafe copy and its destination offset.
4. Compute OFFSET_TO_EIP.
5. Verify with a BBBB payload, then with a cyclic pattern.

**The point:** doing this on a second command proves you've internalized
the method, not just memorized one answer.

## Target 3 — A non-Vulnserver target

Pick one of:

- SLMail 5.5 (POP3 PASS overflow)
- Easy File Sharing Server 7.2 (HEAD request overflow)
- Sync Breeze Enterprise 9.5.16 (HTTP user/password overflow)
- BigAnt Server 2.52 (USV/USR request overflow)

All have public exploits. The point is to derive the offset *without
reading the public exploit*. Find the bug yourself using the techniques
from Exercises 02 and 03.

Steps:

1. Install and start the target in a VM.
2. Send some normal traffic to confirm it works.
3. Attach the debugger.
4. Find the function that handles network input. (Hint: `bp ws2_32!recv`
   still works.)
5. Find the dispatch logic — what does the program do with input?
6. Find the unsafe copy.
7. Derive the offset.
8. Verify with BBBB.
9. **Then** read the public exploit and compare. The point of reading it
   afterward is to check your work, not to be told the answer.

This is the most valuable single hour of OSED prep you will ever do.

## The model update

You can now compute overflow offsets without Mona. That is not the goal —
the goal is that you understand what Mona is computing on your behalf. The
two are very different. After this exercise:

- Mona stops being magic. It becomes a calculator you choose to use.
- Strange bugs (where Mona's heuristics get confused) stop being terrifying.
- You can attack targets that have no Mona-equivalent (e.g. embedded
  firmware, IoT devices, custom protocols).

## Writeup

The deliverable for this exercise is a document titled *"Three overflows,
derived from first principles."* It should contain:

- For each target: the function name/address, the prologue analysis,
  the buffer location, the computed OFFSET_TO_EIP, and the verified value
  from BBBB + pattern_offset.
- A paragraph at the end answering: where, if at all, did your manual
  derivation disagree with Mona? What did you learn from the disagreement?

This document is portable. You will refer back to it for years.

## What this unlocks

Module 01 is complete after this exercise. You can now:

1. Attach a debugger to an arbitrary Windows binary
2. Locate the network input path
3. Identify the vulnerable function
4. Read its frame layout from the disassembly
5. Compute the exact offset to saved return address

The next module (02 — Exploit Mechanics) takes EIP control as a given and
asks: *now what?* SEH overwrites, return address selection under DEP/ASLR,
shellcode placement, payload size constraints, multi-stage exploits.

But none of that matters if you can't reliably do steps 1–5 above. You
now can.
