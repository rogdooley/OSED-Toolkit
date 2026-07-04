# Chapter 9 — Recognizing Library Behavior from Implementation

## 1. Objective

After this chapter you can prove that an unnamed function is `strlen`,
`strcpy`/`strcat`, `memcpy`/`memmove`, or `memset` **from its instructions alone**,
identify the same operations when the compiler *inlines* them as `rep` string
instructions, and — critically — state the *stop condition* and *bound* of any copy,
because that is what decides whether it overflows. This chapter is where "derive,
never assume" earns its keep.

## 2. Background

On the exam and in stripped binaries, functions have no names. A copy loop is just
a loop. The temptation is to glance at a byte-copy-until-zero and declare "that's
`strcpy`" — and then be wrong when it turns out to be a bounded `strncpy`, or a
`strcpy` that also lowercases, or a copy that stops at a delimiter instead of NUL.
The consequences of a wrong guess are severe in exploitation: the *stop condition*
and the *bound* are exactly the properties that determine exploitability, and those
are the properties a name hides.

So we do the opposite of pattern-matching: we read the loop's **element size**,
**direction**, **stop condition**, and **bound**, and we let those four facts
*define* the behavior. If the derived behavior matches `strcpy`'s contract, then it
behaves like `strcpy` — and we say exactly that, with the derivation attached.

## 3. Mental model

Characterize any copy/scan loop by four questions. The answers, not a name,
determine what it is:

```
   1. ELEMENT SIZE  — bytes (movsb/mov al) or dwords (movsd/mov eax)?     -> str* vs mem* / speed
   2. DIRECTION     — pointers increment (forward) or decrement (back)?    -> memmove overlap handling
   3. STOP CONDITION— fixed count? NUL byte? a delimiter? both?           -> mem* vs str* vs strn*
   4. BOUND         — is there a max-count guard, or unbounded?           -> SAFE vs OVERFLOW
```

The behavior lattice that falls out:

```
   stop = fixed count (ECX), no sentinel         -> memcpy / memmove   (bounded by count)
   stop = source NUL, no count cap               -> strcpy / strcat    (UNBOUNDED -> classic overflow)
   stop = source NUL OR count, whichever first   -> strncpy / strlcpy  (bounded)
   scan for NUL, produce a count, no dst          -> strlen
   scan for NUL, produce a count, dst filled from const -> memset (fill) / strcat's find-end phase
   stop = a delimiter byte (e.g., ' ', '\n', '/') -> a tokenizer/parser, NOT a libc copy
```

Two implementations of the same operation exist and you must recognize both:

- **Explicit loop** — a hand-written or `/Od` byte/dword loop with `mov`, `inc`,
  `test`, `jnz`.
- **`rep` string instruction** — the compiler collapses the loop into one
  instruction: `rep movsb`/`rep movsd` (copy ECX units from ESI to EDI),
  `rep stosb`/`rep stosd` (fill EDI with AL/EAX, ECX times), `repne scasb` (scan
  EDI for AL, used to compute lengths). These *are* the loop; ECX is the count,
  ESI/EDI the pointers.

## 4. Assembly examples

```asm
; Example A: prove strlen (scan for NUL, return count) — do NOT assume the name
sub_401000:
    mov     eax, [esp+4]        ; eax = p = arg1 (a pointer)
    mov     edx, eax            ; edx = start (remember where we began)
loc:
    mov     cl, [eax]           ; cl = *p            (ELEMENT SIZE = 1 byte)
    inc     eax                 ; p++                (DIRECTION = forward)
    test    cl, cl              ; *p == 0 ?          (STOP = source NUL)
    jnz     short loc           ; loop while nonzero (BOUND = none; scans to NUL)
    sub     eax, edx            ; count = p - start
    dec     eax                 ; adjust for the post-increment past NUL
    retn                        ; returns count in EAX
```

Four facts: byte element, forward, stops at NUL, no bound, and it *returns a count*
without writing a destination. That is precisely the contract of `strlen`. We
conclude "this behaves as `strlen`" — with the derivation, never as a guess.

```asm
; Example B: prove an UNBOUNDED string copy (strcpy-shaped) — the dangerous one
sub_401030:
    mov     eax, [esp+4]        ; dst
    mov     edx, [esp+8]        ; src
loc:
    mov     cl, [edx]           ; cl = *src         (byte)
    mov     [eax], cl           ; *dst = cl         (COPY, forward)
    inc     edx                 ; src++
    inc     eax                 ; dst++
    test    cl, cl              ; copied byte == 0 ?
    jnz     short loc           ; continue until the NUL was copied
    retn
```

Byte copy, forward, stops when the *source's* NUL is copied, **no count cap**. That
is the `strcpy` contract: it writes `strlen(src)+1` bytes into `dst` regardless of
`dst`'s size. If `dst` is a fixed buffer and `src` is attacker-controlled
(Chapter 7), this overflows. We state that from the loop, and we can now compute the
overflow (Chapter 10). Note we did *not* say "obviously strcpy" — we derived
"unbounded NUL-terminated copy," which *is* strcpy's behavior.

```asm
; Example C: BOUNDED copy (strncpy-shaped) — same shape, one extra guard
sub_401060:
    mov     eax, [esp+4]        ; dst
    mov     edx, [esp+8]        ; src
    mov     ecx, [esp+0Ch]      ; n = max count   <-- the difference from B
loc:
    test    ecx, ecx            ; n == 0 ?
    jz      done                ; BOUND: stop after n bytes
    mov     bl, [edx]
    mov     [eax], bl
    inc     edx
    inc     eax
    dec     ecx                 ; n--
    test    bl, bl
    jnz     loc                 ; also stop at NUL
done:
    retn
```

The single added guard (`n` counter with `test ecx,ecx / jz`) changes the security
story completely: this copy is *bounded*. The shape is nearly identical to Example
B — which is exactly why you must read the bound, not the shape. A one-instruction
difference is the difference between exploitable and safe.

```asm
; Example D: inlined memcpy via rep movsd — an entire loop in two instructions
    mov     esi, src
    mov     edi, dst
    mov     ecx, 40h            ; count = 0x40 DWORDS (= 0x100 bytes!)
    rep     movsd               ; copy ECX dwords ESI->EDI (forward, fixed count)
```

`rep movsd` copies `ECX` *dwords*, so the byte count is `ECX*4 = 0x100`. Stop
condition = fixed count, no sentinel → `memcpy` behavior, bounded by ECX. The
common trap: reading `ecx, 0x40` as 0x40 *bytes*. It's 0x40 dwords. If a tail
`movsb`/`rep movsb` follows, the compiler is copying the remaining `size % 4` bytes
— total size = `dwords*4 + tail_bytes`. Reconstruct the real byte count carefully;
in an overflow it's the difference between a correct and a wrong offset.

```asm
; Example E: inlined memset via rep stos
    xor     eax, eax            ; fill value = 0
    mov     edi, dst
    mov     ecx, 10h
    rep     stosd               ; write EAX to [EDI], 0x10 dwords = 0x40 bytes of zeros
```

Fill with a constant (`eax`), fixed count → `memset(dst, 0, 0x40)`. Often the
zero-init of a struct or buffer right after allocation.

## 5. Equivalent C

```c
// A
size_t my_strlen(const char *p);            // scan to NUL, return count

// B  (unbounded — overflow risk)
char *my_strcpy(char *dst, const char *src);// copy until src NUL, no cap

// C  (bounded)
char *my_strncpy(char *dst, const char *src, size_t n);

// D
memcpy(dst, src, 0x100);                     // rep movsd, ecx=0x40 dwords

// E
memset(dst, 0, 0x40);                        // rep stosd, ecx=0x10 dwords, eax=0
```

## 6. Reverse engineering methodology

For any suspected copy/scan/fill:

1. **Determine element size** — `movsb`/`mov al`/`inc ptr by 1` = bytes; `movsd`/
   `mov eax`/`add ptr, 4` = dwords. (For `rep`, the mnemonic suffix says it.)
2. **Determine direction** — pointers `inc`/`add` (forward) or `dec`/`sub`
   (backward). `std`/`cld` set the direction flag for `rep`; backward copy suggests
   `memmove` handling overlap.
3. **Determine the stop condition** — fixed count in ECX (mem*), source NUL
   (`test/jnz` on the loaded byte → str*), a specific delimiter compare (parser),
   or a combination (strn*).
4. **Determine the bound** — is there a maximum-count guard on the path? If yes,
   what is it and where does it come from (constant, argument, tainted field)? If
   no, it's unbounded.
5. **State the behavior as a contract**, e.g., "byte copy, forward, stops at source
   NUL, unbounded → behaves as `strcpy`; overflows `dst` when `strlen(src) >= sizeof
   dst`." Never a bare name without this.
6. **For `rep`, compute the real byte count** (`ECX * unit`, plus any tail loop).
7. **Confirm in WinDbg** — break before the copy, note `esi`/`edi`/`ecx`, step over,
   and diff the destination memory to see exactly how many bytes moved and where it
   stopped.

## 7. Common compiler idioms

- **`rep movsd` + tail `rep movsb`/`movsb`** — a `memcpy` of `size` bytes split
  into `size/4` dwords and `size%4` bytes. Real size = both parts.
- **`rep stosd`/`rep stosb` with EAX preset** — `memset`; `xor eax,eax` first means
  zero-fill.
- **`repne scasb` with ECX=0xFFFFFFFF, then `not ecx`** — the classic inlined
  `strlen`: scan for AL(=0), then convert the negated counter to a length.
- **Two-phase `strcat`** — a `strlen`/scan phase to find the destination's end,
  then a `strcpy` phase appending. Recognize the seam between "find end" and "copy."
- **`std` before a `rep`** (rare) — backward copy; the compiler is handling
  potential overlap (`memmove`).
- **Small fixed-size copies fully unrolled** — `mov`/`mov`/`mov` of a few dwords
  with no loop; still a `memcpy`, just unrolled because the size was a small
  constant.

## 8. Common mistakes

- **Saying "obviously strcpy."** The whole discipline of this chapter is to *never*
  do this. Derive element size, direction, stop, and bound; then state the behavior.
- **Reading `rep movsd`'s ECX as a byte count.** It's a *dword* count; multiply by
  4. This single error produces overflow offsets that are 4× too small.
- **Missing the bound guard** and calling a `strncpy` a `strcpy` (or vice versa).
  One counter instruction changes everything; look for it explicitly.
- **Ignoring a delimiter stop.** A loop that stops at `' '` or `'\n'` is a parser,
  not a libc copy; treating it as `strcpy` mispredicts how much it copies.
- **Forgetting the `+1` for the NUL** in string copies when computing sizes.
- **Assuming forward direction.** Check the increment/`std`; a backward copy signals
  `memmove` and overlap semantics.

## 9. Exercises

1. A loop: `mov al,[esi] / mov [edi],al / inc esi / inc edi / cmp al, '/' / jnz
   loop`. What is its stop condition, and is it `strcpy`? What does it actually do?
2. `mov ecx, 0x21 / rep movsd`. How many *bytes* are copied? If a `movsb` follows,
   now how many?
3. You find `mov ecx, 0xFFFFFFFF / xor eax,eax / repne scasb / not ecx / dec ecx`.
   Derive what this computes and why the `not`/`dec` are there.
4. Two functions differ only in that one has `dec ecx / jz done` in the loop and one
   doesn't. Which is safe against a fixed-buffer overflow, and why does that one
   instruction decide it?

## 10. Summary

- Never name a copy by shape. Derive four facts — element size, direction, stop
  condition, bound — and let them define the behavior.
- `mem*` = fixed-count (bounded by ECX); `str*` = NUL-terminated (`strcpy` is
  *unbounded* → overflow); `strn*` = bounded by both count and NUL; a delimiter stop
  is a parser.
- Inlined copies appear as `rep movs`/`rep stos`/`repne scas`; ECX is the count in
  *units* (multiply `movsd`/`stosd` by 4), and watch for tail loops.
- The bound is the security-critical fact: one counter instruction separates
  exploitable from safe.
- State behavior as a contract with its derivation, then confirm the byte count and
  stop point in WinDbg.
