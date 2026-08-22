# 5. Loops and Repeated Work

## Learning objectives

- Identify loop header, body, update, and exit condition.
- Distinguish counted loops from sentinel loops.
- Recover induction variables and loop invariants.
- Recognize common scan/copy/compare patterns.

## Concept discussion

Loops answer repeated questions. A counted loop asks, "Have I processed N
elements?" A sentinel loop asks, "Have I reached the marker?" A traversal asks,
"Is there another node/record?"

The compiler may place the condition at the top, bottom, or split across blocks.
Optimized loops may not look like source loops. Focus on:

- Which value changes each iteration?
- Which memory address changes?
- Which condition exits?
- What remains true throughout the loop?

## Common compiler patterns

- `xor ecx,ecx; ... inc ecx; cmp ecx,len; jb loop`: counted loop.
- `mov al,[ecx]; test al,al; jz done; inc ecx`: string scan.
- `rep movsb`: fixed-count byte copy.
- `repne scasb`: sentinel scan, often `strlen`-like.
- Pointer bumping: `add esi,4` instead of index arithmetic.

## Fully annotated example

```asm
sub_401400:
    mov     edx, [esp+4]
    xor     eax, eax
loop_top:
    cmp     eax, [esp+8]
    jae     done
    cmp     byte ptr [edx+eax], 0
    jz      done
    inc     eax
    jmp     short loop_top
done:
    retn
```

Annotated:

```asm
mov edx, [esp+4]
; Buffer pointer.

xor eax, eax
; Index/count starts at zero.

cmp eax, [esp+8] / jae done
; Unsigned bound check: stop when index >= limit.

cmp byte ptr [edx+eax], 0 / jz done
; Sentinel check: stop on NUL.

inc eax
; One byte consumed.
```

The CPU is answering: "How many bytes until either the maximum length is reached
or a zero byte appears?"

The programmer wrote bounded string scanning. The compiler preserves two
assumptions: the limit is unsigned, and the buffer is readable up to either the
terminator or the limit.

## Reverse engineering thought process

Classify the loop:

```text
induction variable: eax
base pointer: edx
access pattern: byte [edx+eax]
upper bound: [esp+8]
sentinel: 0
return: number of bytes scanned
```

Then derive intent: bounded length calculation, not generic looping.

## Common mistakes

- Calling every byte loop `strlen`; this one has a maximum bound.
- Missing that EAX is both index and return value.
- Treating `[esp+8]` as signed because it "looks like an int."
- Ignoring the order of checks. Here, the bound is checked before dereference.

### REP prefix patterns

The `rep` prefix family turns single-byte or single-word instructions into
loops controlled by ECX. These are common in compiler-generated code for
memory operations:

```text
rep movsb     Copy ECX bytes from [ESI] to [EDI], advancing both
rep movsd     Copy ECX dwords from [ESI] to [EDI] (4x faster for aligned data)
rep stosb     Fill ECX bytes at [EDI] with AL
rep stosd     Fill ECX dwords at [EDI] with EAX
repne scasb   Scan [EDI] for AL, decrementing ECX, until found or ECX=0
repe cmpsb    Compare [ESI] vs [EDI] byte-by-byte while equal, up to ECX bytes
```

For exploit analysis, the critical question for any `rep movs` is: does ECX
(the count) exceed the destination capacity? The `rep` prefix blindly copies
for the specified count. If ECX comes from attacker-controlled input, this is
a classic overflow vector.

## Exercises

### Exercise 1

```asm
sub_401450:
    mov     esi, [esp+4]
    mov     ecx, [esp+8]
    xor     eax, eax
again:
    test    ecx, ecx
    jz      done
    add     eax, [esi]
    add     esi, 4
    dec     ecx
    jmp     short again
done:
    retn
```

Questions:

- What is the element size?
- Which value is the induction mechanism?
- What does the function return?

### Exercise 2

```asm
sub_4014A0:
    push    edi
    mov     edi, [esp+8]
    mov     ecx, [esp+0Ch]
    xor     eax, eax
scan:
    test    ecx, ecx
    jz      not_found
    cmp     byte ptr [edi], 0Ah
    jz      found
    inc     edi
    dec     ecx
    jmp     short scan
found:
    mov     eax, edi
not_found:
    pop     edi
    retn
```

Questions:

- What byte value is this loop searching for?
- What does the function return on success vs. failure?
- Is this a counted loop, a sentinel loop, or a bounded sentinel?
- How would you classify this function? (memchr-like, strchr-like, etc.)

### Exercise 3

```asm
sub_4014D0:
    push    esi
    push    edi
    mov     esi, [esp+0Ch]
    mov     edi, [esp+10h]
    mov     ecx, [esp+14h]
    xor     eax, eax
loop_top:
    test    ecx, ecx
    jz      done
    movzx   edx, byte ptr [esi]
    xor     eax, edx
    shl     eax, 1
    inc     esi
    dec     ecx
    jmp     short loop_top
done:
    pop     edi
    pop     esi
    retn
```

Questions:

- What does the XOR/SHL sequence in the loop body compute?
- Is this a copy, a scan, a hash, or something else?
- What is EDI used for? (Trick question.)

## Challenge problems

### Challenge 1

```asm
sub_401490:
    xor     eax, eax
    or      ecx, 0FFFFFFFFh
    repne  scasb
    not     ecx
    dec     ecx
    mov     eax, ecx
    retn
```

Assume EDI points to the input string on entry because the caller set it before
a tail call. This is common in inlined or tail-called helpers where the compiler
leaves EDI set from a prior operation. Recover the pattern and explain the
hidden assumption.

### Challenge 2

```asm
sub_401500:
    push    ebp
    mov     ebp, esp
    push    esi
    mov     esi, [ebp+8]
    mov     ecx, [ebp+0Ch]
    test    ecx, ecx
    jz      short done
    mov     edx, ecx
    shr     ecx, 2
    lea     edi, [esi]
    xor     eax, eax
    rep     stosd
    mov     ecx, edx
    and     ecx, 3
    rep     stosb
done:
    pop     esi
    pop     ebp
    retn
```

This function zeros a buffer. Explain why it uses both `rep stosd` and
`rep stosb`. What is the relationship between the two counts?

## Solutions with reasoning

### Exercise 1 solution

The function processes dword elements because it reads `[esi]` and advances by
four. ECX is a countdown. EAX accumulates a sum. The function returns the sum of
`count` 32-bit integers from the array pointer.

Plausible pseudocode:

```c
unsigned sum(const unsigned *p, unsigned count) {
    unsigned total = 0;
    while (count--) total += *p++;
    return total;
}
```

### Exercise 2 solution

The loop searches for byte `0x0A` (newline / line feed). On success, it
returns the pointer to the found byte (EDI). On failure (ECX reaches zero
without finding 0x0A), it returns NULL (0). This is a bounded sentinel loop --
it has both a count bound (ECX) and a sentinel value (0x0A). This is a
`memchr`-like function searching for a newline character.

Plausible pseudocode:

```c
char *find_newline(const char *buf, unsigned len) {
    while (len--) {
        if (*buf == '\n') return buf;
        buf++;
    }
    return NULL;
}
```

### Exercise 3 solution

The loop XORs each byte of the source buffer into an accumulator, then shifts
the accumulator left by 1 bit. This is a simple rolling hash or checksum --
each byte is mixed in and the result is rotated/shifted to distribute bit
influence. EDI is loaded from the second argument but never used in the loop
body -- it is either dead code, a compiler artifact from register allocation,
or used by caller code that was not shown. The function returns a hash of the
input buffer.

### Challenge 1 solution

This is the classic `strlen` scan idiom using `repne scasb`: set AL to zero, set
ECX to `0xFFFFFFFF` as the maximum scan count, scan for the NUL byte through
memory at EDI, then invert/decrement ECX to produce the length. `scasb` advances
EDI and decrements ECX; it does not update EAX with the count. The hidden
programmer assumption is that the string is NUL-terminated in readable memory.
An exploit developer cares because missing terminators can turn a scan into an
out-of-bounds read before any write occurs.

### Challenge 2 solution

The function zeros `count` bytes starting at the buffer pointer. It splits the
work into two phases for performance: `rep stosd` zeros `count / 4` dwords (the
bulk), then `rep stosb` zeros `count % 4` remaining bytes (the tail). The
`shr ecx, 2` divides by 4 for dword count, and `and ecx, 3` extracts the
remainder for byte count.

This is how MSVC implements `memset(buf, 0, count)` in some optimization
levels. The key insight: `rep stosd` is faster than `rep stosb` for aligned
bulk operations. For exploit analysis, the total bytes written is still `count`
-- the split is an optimization, not a different operation.

## Key takeaways

- Classify every loop by type: counted (ECX countdown), sentinel (scan for a
  value), bounded sentinel (both count and sentinel), or traversal (linked
  list / pointer chain). The type determines the termination guarantee.

- `rep movsb/movsd` is a hardware-accelerated loop. The exploit question is
  always: can ECX (the count) exceed the destination capacity?

- `repne scasb` with `or ecx, -1` is the standard `strlen` idiom. It assumes
  a NUL terminator exists in readable memory -- without one, it reads out of
  bounds.

- The loop body reveals the operation class: `add` accumulates, `xor`/`shl`
  hashes, `cmp` searches, `mov` copies. Identify the operation before
  analyzing bounds.

- Watch for pointer-bumping loops (`add esi, 4`) as an alternative to indexed
  access (`[esi+ecx*4]`). Both access the same data; the bump pattern is
  common in optimized builds.

## See also

- `x86-osed-assembly-reference/06-core-instruction-reference.md` -- REP prefix,
  MOVS, STOS, SCAS, CMPS semantics
- `x86-osed-assembly-reference/10-branches-and-control-flow.md` -- loop
  lowering patterns
- `osed-reversing-guide/05-loops-and-iteration.md` -- loop recovery methodology
- `DRILLS/function_analysis.md` -- loop analysis practice

---
