# Chapter 5 — Reading Loops

## 1. Objective

After this chapter you can recognize a loop from its control-flow graph, identify
the **induction variable** (the thing that advances each iteration) and the
**termination condition**, distinguish counted loops from pointer-walk loops,
handle the compiler's habit of testing the condition at the *bottom*, and mechanically
translate any loop back into `for`/`while` C.

## 2. Background

There are no `for` or `while` keywords in assembly. A loop is just a backward jump:
some conditional branch sends control to an earlier address. Everything else — the
counter, the bound, the body — is ordinary instructions. Your job is to find the
*cycle* in the control-flow graph and then identify the three parts every loop
has, whether written in C or assembly:

- **Initialization** — set up the induction variable before the loop.
- **Body + update** — do work, then advance the induction variable.
- **Test** — decide whether to iterate again (a conditional jump).

Compilers rearrange these. The most important rearrangement: to save one jump per
iteration, the compiler frequently tests the condition at the *bottom* of the loop
and jumps *backward* when it should continue. This "do-while shape" is the default
for `-O2` and common even at `-Od`, so learn to read it as the norm, not the
exception.

## 3. Mental model

Two canonical shapes. First, the **top-tested** loop (matches `while`/`for`
literally):

```
   init
 loc_top:
   cmp   counter, bound      ; test FIRST
   jge   loc_end             ; exit if done
   ...body...
   inc   counter             ; update
   jmp   loc_top             ; unconditional back-edge
 loc_end:
```

Second, the **bottom-tested** loop (the compiler's favorite; a `do {} while`
shape even when the source was a `for`):

```
   init
 loc_top:
   ...body...
   inc   counter             ; update
   cmp   counter, bound      ; test LAST
   jl    loc_top             ; conditional BACK-edge: continue while <
 loc_end:
```

The tell for a loop is the **back-edge**: a jump whose target address is *lower*
than the jump itself. Find the back-edge and you've found the loop. Then:

- Whatever the back-edge's condition compares is the **termination test**.
- The variable that is modified every iteration and appears in that test is the
  **induction variable**.
- Everything between the loop's top and the update is the **body**.

If the compiler was smart, it may have added a **guard** before a bottom-tested
loop (`cmp; jge loc_end` before entering) so a zero-trip `for` still runs zero
times. Presence of a guard tells you the source was a `for`/`while` (which can run
0 times); absence tells you it was likely a `do {} while` (runs at least once).
Another derivation, straight from structure.

## 4. Assembly examples

```asm
; Example A: counted loop summing an int array — bottom-tested
    xor     eax, eax            ; sum = 0        (accumulator)
    xor     ecx, ecx            ; i = 0          (induction variable)
loc_top:
    add     eax, [edx+ecx*4]    ; sum += arr[i]  (*4 => int elements, Chapter 2)
    inc     ecx                 ; i++
    cmp     ecx, 10h            ; compare i to 16
    jl      short loc_top       ; continue while i < 16  (signed: 'jl')
    ; eax now holds the sum
```

Derivation, step by step:
- `xor ecx, ecx` then `inc ecx` each pass, tested by `cmp ecx, 0x10 / jl` → `ecx`
  is the induction variable `i`, running `0..15`.
- `add eax, [edx+ecx*4]` accumulates 4-byte elements of the array based at `edx`
  into `eax` → `sum += arr[i]`, `arr` is `int*`.
- `jl` (signed) → `i` is a signed `int`, bound `0x10 = 16`.
- No guard before `loc_top`, but the range is a constant 16, so this reads
  cleanly as a `for (i=0; i<16; i++)`.

```asm
; Example B: pointer-walk loop (strlen-shaped) — no counter, a moving pointer
    mov     eax, [ebp+8]        ; eax = p = arg1 (a char*)
loc_top:
    mov     cl, [eax]           ; cl = *p
    inc     eax                 ; p++            (element size 1 => char*)
    test    cl, cl              ; *p == 0 ?
    jnz     short loc_top       ; loop while byte != 0
    sub     eax, [ebp+8]        ; length = p - start
    dec     eax                 ; ... minus 1 (we advanced past the NUL)
```

Here the induction variable is the *pointer* `eax`, not an integer counter. The
termination test is `test cl, cl / jnz` — "continue while the byte is nonzero,"
i.e., stop at the NUL terminator. The trailing `sub/dec` recovers the count from
the pointer delta. We derive "this computes string length" from the structure —
NUL-terminated walk, pointer difference — *not* from a name. (Chapter 9 formalizes
this.)

```asm
; Example C: nested loop (matrix/byte-block) — two induction variables
    xor     esi, esi            ; row = 0
outer:
    xor     edi, edi            ; col = 0  (reset each outer pass)
inner:
    ; ... body uses [base + esi*rowstride + edi] ...
    inc     edi
    cmp     edi, ecx            ; col < width ?
    jl      inner
    inc     esi
    cmp     esi, edx            ; row < height ?
    jl      outer
```

Two back-edges, two induction variables. The inner counter is *re-initialized*
inside the outer loop (`xor edi, edi` under `outer:`) — that reset is how you tell
an inner loop from a continuation of the outer.

## 5. Equivalent C

```c
// A
int sum = 0;
for (int i = 0; i < 16; i++) sum += arr[i];

// B
char *p = s;
while (*p) p++;
int len = (int)(p - s) - 1 + 1;  // == p - s; see note below

// C
for (int row = 0; row < height; row++)
    for (int col = 0; col < width; col++)
        process(base[row*rowstride + col]);
```

Note on B: the assembly did `p++` *before* the test, so at exit `p` points one past
the NUL; `p - start` overcounts by one and the `dec` corrects it, yielding the true
length. Working the arithmetic out is the point — don't hand-wave it.

## 6. Reverse engineering methodology

1. **Find the back-edge.** Scan for a conditional (or unconditional) jump whose
   target is above it. IDA draws this as an arrow curving upward; use graph view.
2. **Name the induction variable.** Which register/local is updated every
   iteration (`inc`, `add`, `p++`) *and* appears in the loop's test?
3. **Read the termination condition** off the back-edge's `cmp`/`test` + jump.
   Note signed vs unsigned (Chapter 1) — it's the loop variable's type.
4. **Delimit the body** = instructions between the loop top and the update.
5. **Classify:** counted (integer counter vs a bound) or pointer-walk (moving
   pointer vs a sentinel like NUL). Element size comes from the scale/increment.
6. **Check for a guard** before the loop to decide `for/while` (can run 0×) vs
   `do-while` (runs ≥1×).
7. **Reconstruct** the C, then **verify a few iterations in WinDbg**: break at the
   top, `r` the counter, step, watch it advance and the accumulator/pointer change.

## 7. Common compiler idioms

- **Bottom-tested loops** (`do-while` shape) as the default — the update and test
  live at the bottom with a conditional back-edge.
- **Loop guard** `cmp; jge end` before the loop to preserve zero-trip semantics of
  a `for`.
- **`dec ecx; jnz`** — count-down loop; the compiler often counts down to zero
  because comparing against zero is free (the `dec` sets ZF). If you see a counter
  running *downward*, the original C likely counted *up* and the compiler reversed
  it — the iteration count is what matters, not the direction.
- **`rep movs/stos/scas`** — an entire loop in one instruction, counted by ECX.
  Recognize it as a copy/fill/scan (Chapter 9), not a scalar op.
- **Strength-reduced index** — instead of recomputing `base + i*4`, the compiler
  keeps a running pointer and does `add reg, 4` each pass. The counter disappears
  into pointer increments; reconstruct `i` from the pointer delta.
- **Unrolling** (`-O2`) — the body is duplicated N times with the counter advanced
  by N; don't mistake the repetition for distinct logic.

## 8. Common mistakes

- **Missing the back-edge and reading a loop as straight-line code.** Always
  resolve where jumps go; a loop read linearly is nonsense.
- **Picking the wrong induction variable** — e.g., calling the accumulator (`eax`
  summing) the counter. The induction variable is the one in the *termination
  test*.
- **Ignoring the pre-update-vs-post-update order**, which throws off off-by-one
  reconstructions (see the strlen note). Track *when* the update happens relative
  to the test.
- **Reading a count-down loop as if the source counted down.** The compiler
  reverses loops for free zero-compares; the trip count is the invariant, not the
  direction.
- **Treating an inner-loop counter reset as part of the outer body.** The `xor
  edi, edi` at the top of the inner loop is initialization, marking a nested loop.

## 9. Exercises

1. Rewrite Example A as a `while` loop and as a count-*down* loop. Confirm all
   three run the same 16 iterations.
2. In Example B, if the pre-loop value of `[ebp+8]` is a pointer to `"AB\0"`, trace
   `eax` and `cl` each iteration and compute the final returned length by hand.
3. You see `dec esi / jnz loc_top` with no `cmp`. What is the termination
   condition, and what does the original loop count look like?
4. Given a loop that does `add edi, 4` each pass and never uses an integer counter,
   explain how to recover the logical index `i` and the element type.

## 10. Summary

- A loop is a back-edge (a jump to a lower address); find it first.
- Every loop has init, body+update, and test; the compiler often puts the test at
  the *bottom* (do-while shape) and may add a guard for zero-trip `for`s.
- The **induction variable** is the thing updated each pass *and* named in the
  termination test; the **element type** comes from its scale/increment.
- Counted loops test a counter against a bound; pointer-walk loops test a moving
  pointer against a sentinel (often NUL).
- Watch update-vs-test order for off-by-ones, and reconstruct count-down loops by
  trip count, not direction. Verify a few iterations in WinDbg.
