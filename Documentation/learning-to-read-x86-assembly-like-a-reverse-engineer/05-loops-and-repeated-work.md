# Loops and Repeated Work

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

## Exercises

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

## Challenge problems

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

## Solutions with reasoning

Exercise solution:

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

Challenge solution:

This is the classic `strlen` scan idiom using `repne scasb`: set AL to zero, set
ECX to `0xFFFFFFFF` as the maximum scan count, scan for the NUL byte through
memory at EDI, then invert/decrement ECX to produce the length. `scasb` advances
EDI and decrements ECX; it does not update EAX with the count. The hidden
programmer assumption is that the string is NUL-terminated in readable memory.
An exploit developer cares because missing terminators can turn a scan into an
out-of-bounds read before any write occurs.

---
