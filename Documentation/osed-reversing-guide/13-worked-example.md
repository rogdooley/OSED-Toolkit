# Chapter 13 — Capstone: Reasoning About an Unknown Function End to End

## Objective

The previous chapters each isolated one skill. This one puts them together on a
single unknown function, thinking aloud the way you actually would at the keyboard.
The point is not the answer — it's the *process*: how a fact ledger grows, how each
question from the [playbook](how-to-think-while-reversing.md) fires in turn, and how
a hypothesis gets promoted to a fact only when the evidence closes the gap. Read
this last, after Chapters 0–12, as a demonstration of the whole method rather than a
new topic. It does not follow the ten-section chapter template; a worked example has
its own shape.

## The specimen

IDA dropped us at `sub_401080` with no symbols. Here is exactly what we see:

```asm
sub_401080 proc near
    push    ebp
    mov     ebp, esp
    sub     esp, 44h
    push    esi
    push    edi
    mov     esi, [ebp+8]            ; (1)
    movzx   eax, byte ptr [esi]     ; (2)
    cmp     eax, 80h                ; (3)
    ja      short loc_4010B8        ; (4)
    lea     edi, [ebp-40h]          ; (5)
    lea     esi, [esi+1]            ; (6)
    mov     ecx, eax                ; (7)
    rep     movsb                   ; (8)
    mov     byte ptr [edi], 0       ; (9)
    lea     eax, [ebp-40h]          ; (10)
    push    eax                     ; (11)
    call    sub_401200              ; (12)
    add     esp, 4                  ; (13)
    xor     eax, eax                ; (14)
    jmp     short loc_4010BD        ; (15)
loc_4010B8:
    mov     eax, 0FFFFFFFFh         ; (16)
loc_4010BD:
    pop     edi                     ; (17)
    pop     esi                     ; (18)
    mov     esp, ebp                ; (19)
    pop     ebp                     ; (20)
    retn                            ; (21)
sub_401080 endp
```

We will keep two columns as we go — **Facts** (what the instructions force) and
**Hypotheses** (stories we're entertaining) — and refuse to blur them.

## Pass 1 — boundary and frame (Chapters 3, 4)

*Question: where does this unit begin and end, and what's the frame?*

Lines (1)`push ebp / mov ebp, esp / sub esp, 44h` is the standard prologue; lines
(19–21)`mov esp,ebp / pop ebp / retn` is the matching epilogue. So this is one
framed function with `0x44` bytes of locals. The `push esi / push edi` right after
the prologue, balanced by `pop edi / pop esi` before the epilogue, are callee-saved
register preservation — scaffolding, not arguments. The bare `retn` (no operand)
means the *caller* cleans the stack → `__cdecl`.

The function reads `[ebp+8]` and nothing higher, so it takes **one argument**. It
returns in EAX along two paths: `0` (line 14) on the fall-through, `0xFFFFFFFF`
(line 16) on the branch. Two return values, one of them `-1`, strongly suggests a
**success/failure convention**.

> **Facts:** framed function; 0x44 bytes locals; one stack argument at `[ebp+8]`;
> `__cdecl`; returns 0 or -1 in EAX.
> **Hypotheses:** returns a success(0)/failure(-1) status; the argument is a
> pointer (we'll test that next).

## Pass 2 — classify the argument and follow the data (Chapters 2, 7)

*Question: what is `[ebp+8]`, and where does it come from / go?*

Line (1) puts it in ESI. Line (2) does `movzx eax, byte ptr [esi]` — it
*dereferences* ESI. A value that gets dereferenced is a pointer (playbook: "every
pointer came from somewhere; recognize pointers by dereference"). So the argument is
a pointer to bytes. We don't yet know the caller, but the first thing the function
does is read *byte 0* of whatever it points at.

To know if this is attacker-controlled, we'd xref `sub_401080` (`X` in IDA) and walk
up toward a source. Suppose that xref chain leads back to a `recv` buffer — a very
common shape. Then `[ebp+8]` points at **attacker-controlled input**, and byte 0 is
the first tainted byte. We'll carry that as a hypothesis until the xref confirms it,
but we'll reason about both cases.

Line (2) `movzx eax, byte ptr [esi]` — zero-extend a single byte into EAX. Two facts
fall out: the source element is a **byte** (`unsigned char`, because `movzx` not
`movsx`), and after this EAX holds a value in `0..255`. The `movzx` (not a plain
`mov al`) tells us the compiler wanted a clean 32-bit value — the byte is about to
be used in a 32-bit comparison, so this byte is being *interpreted as a number*, not
copied as a character.

> **Facts:** `[ebp+8]` is a pointer; the function reads its byte 0 as an unsigned
> value `0..255` into EAX.
> **Hypotheses:** the pointer is attacker-controlled input (pending xref); byte 0 is
> a count/length field, given it's read as a number.

## Pass 3 — the branch: where trust is established (Chapters 6, 7)

*Question: what question does this branch ask, and where does each edge go?*

Lines (3–4): `cmp eax, 80h / ja loc_4010B8`. The `ja` is **unsigned** (Chapter 1 —
signedness leaks through the jump). So the test is: *is the unsigned value > 0x80?*
If yes, jump to (16) which sets EAX = -1 and returns. If no, fall through into the
copy.

This is a **validation** — a trust boundary (playbook: "where is trust
established?"). The function refuses values above `0x80` (128). Because our byte was
`0..255`, the accepted path guarantees the value in EAX is now `0..0x80`. Note the
compiler used `ja`, not `jg`; had it used a signed compare, a "negative" byte could
slip through — but `movzx` already made that impossible here, and the unsigned `ja`
is consistent with a length. The evidence coheres: this is a length being
bounds-checked to `<= 0x80`.

> **Facts:** unsigned check rejects value > 0x80; on the accepted path EAX ∈
> `0..0x80`; the reject path returns -1.
> **Hypotheses (now stronger):** byte 0 is a length field, validated to ≤ 0x80.

## Pass 4 — the copy: identify the function by contract (Chapter 9)

*Question: what does the copy actually do — element size, direction, stop, bound?*

Lines (5–8) set up and run the copy. Answer the four questions from Chapter 9
instead of guessing a name:

- **Destination** (5): `lea edi, [ebp-40h]` — EDI is the address of a local at
  `ebp-0x40`. Address-taken local fed to a copy → this is a **buffer**, and its
  offset from EBP is `0x40`.
- **Source** (6): `lea esi, [esi+1]` — advance the pointer past byte 0. So the copy
  reads from `input+1`, i.e., the bytes *after* the length field.
- **Count** (7): `mov ecx, eax` — ECX = the validated length (`0..0x80`).
- **The copy** (8): `rep movsb` — copy **ECX bytes** (movs*b* = bytes, so the count
  is in bytes, not dwords — no ×4 trap here) from ESI to EDI, forward. Stop
  condition = fixed count; no sentinel.

Element size = byte, direction = forward, stop = fixed count, bound = ECX (the
length). That is the **contract of `memcpy(dst, src, len)`**. We say exactly that,
with the derivation — not "looks like memcpy."

Line (9) `mov byte ptr [edi], 0` — after `rep movsb`, EDI points one past the last
copied byte, so this writes a NUL terminator at `dst[len]`. That tells us the
destination is being treated as a **C string**: the function copies `len` bytes then
NUL-terminates. Total bytes written to the destination = `len + 1`.

> **Facts:** copies `len` bytes (byte-wise, forward, count-bounded) from `input+1`
> into a buffer at `ebp-0x40`, then writes a NUL at offset `len`. Writes `len+1`
> bytes total. Behaves as `memcpy` + explicit NUL-terminate.
> **Hypotheses:** the buffer is meant to hold a NUL-terminated copy of an
> input field.

## Pass 5 — the tail and the return (Chapters 4, 8)

*Question: what happens to the buffer, and what does the function output?*

Lines (10–13): `lea eax, [ebp-40h] / push eax / call sub_401200 / add esp, 4` — take
the buffer's address and pass it (one arg, caller-cleaned → cdecl) to
`sub_401200`. So the buffer is an **output** consumed downstream; to fully
understand side effects we'd analyze `sub_401200` next (it's the real consumer of
our now-populated buffer). For this function, the side effect is "fills a local
buffer and hands it to `sub_401200`."

Lines (14–15) set EAX = 0 and jump to the common epilogue → success path returns 0.

> **Facts:** on success, the filled buffer is passed to `sub_401200` and the
> function returns 0; on rejection it returns -1 without copying.

## Pass 6 — the trust violation (Chapter 10)

Now the whole picture is on the table, and the bug becomes a *derivation*, not a
hunch. Line up two facts we established independently:

- The **check** (Pass 3) permits `len` up to **0x80 = 128**.
- The **destination** (Pass 4) is the buffer at `ebp-0x40`, which is only **0x40 =
  64 bytes** (its distance below EBP, and the frame reserved `0x44`).
- The **copy** (Pass 4) writes `len + 1` bytes into it.

*Question (playbook): where is trust violated? Is destination capacity verified?*

The validation checks the length against **0x80**, but the buffer holds only
**0x40**. The check guards the *wrong size*. This is the playbook's "most bugs are
broken checks, not missing ones" in the flesh — there *is* a bounds check, and it's
simply wrong. An attacker who sets byte 0 to anything in `0x41..0x80` copies 65–128
bytes into a 64-byte buffer: a stack overflow.

Now derive the offset (Chapter 10). The buffer starts at `ebp-0x40`, so the distance
to the saved return address at `[ebp+4]` is `0x40 + 4 = 0x44 = 68` bytes. But wait —
we `push esi / push edi` in the prologue, and they were pushed *after* `mov ebp,esp`,
so they sit **below** EBP (at `[ebp-0x48]`, `[ebp-0x4C]`), not between the buffer and
the saved return address. They don't add to the buffer→retaddr distance. (This is
exactly the kind of thing you do **not** assume — you read where the pushes landed
relative to EBP.) So the static offset to EIP is `0x44`, and the attacker controls
up to `0x80` bytes of copy — more than enough to reach and overwrite it.

There is no `/GS` cookie in the prologue (no `mov eax, __security_cookie / xor eax,
ebp`), so a straight return-address overwrite is not blocked here.

> **Facts:** bounds check permits 0x80 but destination is 0x40 → overflow;
> attacker-controlled bytes (input+1) are the copy source; static offset from
> buffer start to saved return address = 0x44; no `/GS`.
> **Hypotheses to confirm dynamically:** EIP is controllable at offset 0x44 with a
> length byte ≥ 0x45.

## Pass 7 — close the loop in WinDbg (Chapter 12)

Static reasoning gave a falsifiable claim. Prove it. Break at `sub_401080` (mind the
IDA-base ↔ WinDbg-base conversion), then drive it:

```
0:000> bp <module>+0x1080
0:000> g
0:000> r esi                       ; confirm esi = our input pointer
0:000> db @esi L10                 ; byte 0 = our length, then the payload bytes
0:000> dd @ebp-0x40 L18            ; watch the destination buffer fill after rep movsb
```

Send a packet whose byte 0 is `0x50` (80 — passes the ≤0x80 check, exceeds the 0x40
buffer) followed by a cyclic pattern. Let it run to the `ret`:

```
0:000> r eip
eip=<pattern slice>
0:000> !py mona pattern_offset <slice>
[+] found at offset 68             ; 68 = 0x44 — matches the static derivation
```

Then replace offset-0x44's four bytes with `42 42 42 42` and confirm `eip=42424242`.
The hypothesis is now a fact: the offset is `0x44` and EIP is controllable. The loop
has closed.

## What just happened

Nothing in this chapter required recognizing a shape on sight. Every conclusion was
forced by instructions and cross-checked, and the two dangerous shortcuts — "that's
strcpy/memcpy" and "the frame size is the offset" — were each replaced by a
derivation. The bug (a real, correct bounds check guarding the wrong buffer size)
surfaced not from scanning for scary calls but from laying two independently-derived
facts side by side: *check allows 0x80, buffer holds 0x40*. That is the entire
method:

1. Establish boundary and frame → 2. classify and follow the data → 3. read each
branch as a question → 4. identify called behavior by contract, not name → 5. find
the output/side effects → 6. lay facts side by side to expose the trust violation →
7. confirm the load-bearing number in the debugger.

Keep the fact/hypothesis ledger the whole way, promote nothing without evidence, and
any unknown x86 function yields to the same seven passes.
