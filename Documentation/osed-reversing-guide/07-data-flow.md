# Chapter 7 — Data Flow and Following Attacker-Controlled Input

## 1. Objective

After this chapter you can trace a value from where it enters a program to where
it is used, distinguish data you *control* from data you don't, and identify the
exact instructions where attacker-controlled input reaches a dangerous operation
(a copy into a fixed buffer, an indirect call, an index into an array). This is the
analysis that turns "I understand this function" into "I found the bug."

## 2. Background

Reverse engineering for exploitation is fundamentally a **taint-tracking** problem:
you mark the bytes you control (the *source*), follow every instruction that moves
or transforms them, and find where they reach a *sink* — an operation whose
misbehavior you can leverage. The compiler didn't label any of this; you rebuild
the data-flow graph yourself from `mov`s, arithmetic, and calls.

Two directions of analysis, used together:

- **Forward (source → sink):** start at input (`recv`, `ReadFile`, `fread`, a
  command argument) and follow where those bytes go. Good for "what can this input
  reach?"
- **Backward (sink → source):** start at a dangerous operation (a copy with no
  bound, an indirect `call eax`) and ask "where did these operands come from? Do I
  control them?" Good for "is this exploitable?"

You will constantly switch between the two.

## 3. Mental model

Think of every value as *tainted* or *clean*, and propagate taint through
instructions the way the CPU propagates data:

```
   SOURCES (taint enters)              SINKS (taint becomes power)
   ------------------------            ----------------------------
   recv / recvfrom                     copy into fixed stack buffer   -> overflow
   ReadFile / fread / fgets            memcpy/strcpy with tainted len -> overflow
   GetEnvironmentVariable              index: arr[tainted]            -> OOB r/w
   command-line / argv                 call [tainted] / jmp tainted   -> control hijack
   registry / file contents            format string = tainted        -> fmt bug
   parsed protocol fields              allocation size = tainted      -> heap issues
```

Taint propagation rules (how the marker follows the data):

- **`mov dst, src`** — taint flows src → dst. Copies carry taint.
- **Arithmetic** (`add`, `sub`, `lea`, shifts) — result is tainted if any operand
  is. `len = tainted + 4` is still tainted (and you control it, offset by 4).
- **`[tainted]` load** — reading through a tainted *pointer* is OOB read power;
  the *loaded value* is tainted too.
- **Truncation/masking** (`and`, `movzx al`) — still tainted but with reduced range
  (e.g., `and eax, 0xFF` = you control one byte, 0..255).
- **Overwrite by a constant** clears taint (`xor eax, eax`, `mov eax, 5`).
- **A validated value is partially cleaned:** after `cmp len, 40h / ja reject`,
  along the *accepted* path `len <= 0x40` — the check *constrains* your control.
  Finding where checks are missing or wrong is the whole game.

The crucial exploitation question at every sink: **do I control this operand, and
with what constraints?** Not "is it a variable" but "how many of these bytes, and
which values, can I set?"

## 4. Assembly examples

```asm
; A network handler: recv into a stack buffer, then copy it. Trace the taint.
    lea     eax, [ebp-208h]     ; eax = &recvbuf  (a 0x200-byte stack buffer)
    push    200h                ; len = 0x200  (bounded read into recvbuf)
    push    eax                 ; buf = &recvbuf
    push    [ebp+sock]          ; socket
    call    recv                ; <-- SOURCE: recvbuf[0..0x1FF] now tainted
    mov     [ebp-4], eax        ; eax = bytes received (also tainted: attacker-influenced)

    ; ... later ...
    lea     eax, [ebp-208h]     ; eax = &recvbuf (tainted data)
    push    eax                 ; src = tainted
    lea     ecx, [ebp-40h]      ; ecx = &smallbuf  (only 0x40 bytes!)
    push    ecx                 ; dst = 64-byte buffer
    call    sub_401500          ; a copy routine (Chapter 9 to confirm it's strcpy-like)
```

Data-flow reading:
- `recv` fills `recvbuf` at `[ebp-0x208]` with up to `0x200` attacker bytes →
  **source**. That read is *bounded* (0x200), so no overflow yet.
- The bytes are then handed as `src` to `sub_401500`, whose `dst` is a **0x40-byte**
  buffer at `[ebp-0x40]`. If `sub_401500` copies until a NUL (strcpy-shaped) with
  no length cap, then up to `0x200` tainted bytes flow into a `0x40` destination →
  **overflow at the sink**. The vulnerability lives at the *mismatch* between the
  source size and the destination size, which you found by following the buffer.
- To confirm, you'd analyze `sub_401500` (Chapter 9) to prove it's an unbounded
  copy, then compute the offset from `smallbuf` to the return address (Chapter 10).

```asm
; Tainted value used as an array index -> out-of-bounds
    movzx   eax, byte ptr [ebp-208h]   ; eax = recvbuf[0]  (one tainted byte, 0..255)
    mov     ecx, ds:table[eax*4]       ; read table[attacker_byte]  -> OOB if table<256 entries
    call    ecx                        ; INDIRECT CALL through tainted table entry!
```

Backward reading from the sink `call ecx`: `ecx` came from `table[eax*4]`, `eax`
came from `recvbuf[0]` (tainted). So the *call target* is selected by an attacker
byte. If `table` has fewer than 256 entries, `eax` reads past it — and even in
bounds, you're steering the dispatch. This is a control-flow sink found purely by
walking operands backward.

## 5. Equivalent C

```c
// First example
char recvbuf[0x200];
int n = recv(sock, recvbuf, 0x200, 0);   // bounded source
char smallbuf[0x40];
copy_until_nul(smallbuf, recvbuf);       // sink: no length check -> overflow

// Second example
unsigned char idx = recvbuf[0];          // tainted index
void (*fn)() = table[idx];               // OOB if idx >= COUNT
fn();                                     // tainted indirect call
```

## 6. Reverse engineering methodology

1. **Enumerate the sources.** Search Imports/Strings for input functions
   (`recv`, `ReadFile`, `fread`, `GetEnvironmentVariable`, `RegQueryValue`, argv).
   Each return buffer/value is initial taint. In IDA, list xrefs to these imports.
2. **Propagate forward.** From each source buffer, follow every `mov`, `lea`,
   arithmetic op, and `call` that consumes it. Rename tainted locals in IDA
   (`recvbuf`, `tainted_len`) so the taint is visible as you go.
3. **Enumerate the sinks.** Copies into fixed buffers, `memcpy`/`strcpy`-shaped
   routines, `sprintf`, array indexing, allocation sizes, indirect calls/jumps,
   format-string args.
4. **At each sink, ask the control question:** which operands are tainted, and what
   constraints were imposed on the path here (bounds checks, length caps,
   character filters)?
5. **Find the gap.** The bug is where taint reaches a sink *without* an adequate
   check — an unbounded copy, a bounds check using the wrong sign/size, a filter
   that misses a case.
6. **Work backward to confirm** from the sink's operands to the source, making sure
   the path is real (reachable, not gated by a check you can't satisfy).
7. **Prove it in WinDbg.** Set a breakpoint at the sink, send a marker input
   (`AAAA...` / cyclic pattern), and confirm your controlled bytes are exactly
   where you predicted, in the register/memory the sink uses.

## 7. Common compiler idioms

- **Bounds check before use:** `cmp len, MAX / ja reject` — along the accepted
  path, `len <= MAX`. Its *presence* constrains you; its *absence* is the bug.
- **Signed/unsigned length bugs:** a length compared with `jg`/`jl` (signed) but
  used as an unsigned size in a copy — a negative "length" passes the check then
  becomes a huge `size_t`. The mismatch between the *check's* signedness and the
  *use's* signedness is a classic finding (Chapter 1's jump-signedness reading
  pays off here).
- **Length taken from the input itself:** a protocol field read from `recvbuf`
  then used as the copy length — tainted length + tainted data is the strongest
  primitive.
- **`movzx`/`and` narrowing** — tells you exactly how many bits of a value you
  control.
- **Copies via `rep movs`** with a tainted `ecx` — the count is attacker-controlled
  (Chapter 9).

## 8. Common mistakes

- **Stopping at the first `mov`.** Taint flows through many hops; follow it to the
  actual sink, not just one copy.
- **Assuming a bounds check is correct because it exists.** Check its *sign*, its
  *width* (`cmp cx` vs `cmp ecx`), and whether it guards the path that reaches the
  sink. Many bugs are broken checks, not missing ones.
- **Treating a `recv` with a size argument as automatically safe.** The `recv` is
  bounded, but the *next* copy of that buffer may not be. Safety is per-operation.
- **Ignoring return values as taint.** `recv` returns a byte count you influence;
  used as a length or index, it's tainted too.
- **Confusing "reads attacker data" with "attacker controls the operand."** A value
  derived from input but clamped (`and eax, 7`) gives you only 3 bits — real, but
  limited. State the constraint precisely.

## 9. Exercises

1. In the first example, exactly which bytes do you control at the sink, how many,
   and what determines whether the overflow triggers (hint: the copy's stop
   condition)?
2. A length field is loaded with `movzx eax, word ptr [recvbuf+4]` and checked with
   `cmp eax, 0x100 / jg reject`, then passed to a copy. Is the check sound? Consider
   the sign and the width of the load vs the compare.
3. Trace backward from `call edx` where `edx = [esi+8]`, `esi = [ebp-10h]`, and
   `[ebp-10h]` was filled from `recv`. What is the exploit primitive, and what must
   be true for it to work?
4. Distinguish, with an example, a value that is "tainted but constrained to 0..255"
   from one that is "fully attacker-controlled 32 bits." Why does the distinction
   change the exploit?

## 10. Summary

- Exploitation-oriented RE is taint tracking: mark input (sources), follow it
  through `mov`/arithmetic/calls, find where it reaches a dangerous operation
  (sinks).
- Analyze both directions: forward (what can input reach?) and backward (do I
  control this sink's operands?).
- Taint flows through copies and arithmetic, is narrowed by masks, and is
  *constrained* (not necessarily cleaned) by validation checks.
- The bug lives at the gap: taint reaching a sink without an adequate check — often
  a *broken* check (wrong sign/width) rather than a missing one.
- Always state precisely how many bytes you control and with what constraints, then
  confirm the controlled bytes' location at the sink in WinDbg.
