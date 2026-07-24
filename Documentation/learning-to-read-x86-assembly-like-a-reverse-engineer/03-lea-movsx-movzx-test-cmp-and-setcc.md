# LEA, MOVSX, MOVZX, TEST, CMP, and SETcc

## Learning objectives

- Explain why `lea` often means arithmetic rather than pointer dereference.
- Use `movsx` and `movzx` to infer signedness and source width.
- Read `test`, `cmp`, and `setcc` as boolean and range questions.
- Avoid turning flag-setting instructions into fake source statements.

## Concept discussion

These instructions are semantic clues. They reveal the compiler's type and range
assumptions:

- `movzx eax, byte ptr [ecx]`: source is an unsigned byte promoted to int.
- `movsx eax, word ptr [ecx]`: source is a signed short promoted to int.
- `test eax,eax`: check zero, null, or false.
- `cmp eax, 80h` + `ja`: unsigned greater-than.
- `cmp eax, 80h` + `jg`: signed greater-than.
- `setnz al`: materialize a boolean result into a byte.

The compiler emits these because C does not compare abstract "values"; it
compares values of a width and signedness after promotion.

## Common compiler patterns

- `lea eax, [ecx+ecx*4]`: multiply by 5.
- `lea eax, [edx+eax*4+8]`: array element address or structure-member address.
- `movzx eax, al`: clear high bits after byte arithmetic.
- `test reg, reg; jz`: null/zero check.
- `cmp reg, imm; setcc al; movzx eax, al`: return boolean as int.

## Fully annotated example

```asm
sub_401220:
    mov     ecx, [esp+4]
    movsx   eax, word ptr [ecx+4]
    lea     edx, [eax+eax*2]
    cmp     edx, 30h
    setle   al
    movzx   eax, al
    retn
```

Annotated:

```asm
mov ecx, [esp+4]
; Argument, likely pointer because it is dereferenced next.

movsx eax, word ptr [ecx+4]
; Read a 16-bit signed field at offset +4 and promote it to 32 bits.

lea edx, [eax+eax*2]
; Compute value * 3. No memory read.

cmp edx, 30h
setle al
; Signed comparison: is field*3 <= 48?

movzx eax, al
; Return boolean as 0 or 1.
```

The CPU is answering: "Does the signed 16-bit field at offset 4, multiplied by
three, fit under a signed threshold?"

The programmer likely wrote a small validation predicate. The compiler assumes
signed behavior matters because it chose `movsx` and signed `setle`.

## Reverse engineering thought process

When you see `lea`, ask: "Is the result later dereferenced?" If no, it may just
be arithmetic. When you see `movsx`/`movzx`, record source width and signedness.
When you see `setcc`, identify which compare produced the flags and whether the
condition is signed or unsigned.

## Common mistakes

- Saying `lea` always means "load pointer."
- Losing signedness by rewriting everything as `int`.
- Treating `setcc` as a branch; it creates data, not control flow.
- Ignoring high-register cleanup before boolean returns.

## Exercises

```asm
sub_401250:
    mov     eax, [esp+4]
    movzx   ecx, byte ptr [eax+8]
    lea     edx, [ecx+ecx*4]
    cmp     edx, 64h
    seta    al
    movzx   eax, al
    retn
```

Questions:

- What is the width and signedness of the field?
- What arithmetic is being performed?
- What boolean is returned?

## Challenge problems

```asm
sub_401280:
    mov     ecx, [esp+4]
    movsx   eax, byte ptr [ecx+1]
    test    eax, eax
    jns     short ok
    neg     eax
ok:
    cmp     eax, 7Fh
    setbe   al
    movzx   eax, al
    retn
```

Recover the programmer-level question without writing a line-by-line
translation.

## Solutions with reasoning

Exercise solution:

The field at offset `+8` is an unsigned byte. It is multiplied by 5 using LEA.
The function returns whether `field * 5 > 100` using an unsigned comparison
(`seta`).

Plausible pseudocode:

```c
int too_large(const unsigned char *p) {
    return p[8] * 5u > 100u;
}
```

Challenge solution:

The function reads a signed byte at offset `+1`, computes its absolute value, and
returns whether that absolute value is `<= 127`. The interesting semantic clue is
not `neg`; it is the pair `movsx` and `jns`, which shows the original byte was
signed. The programmer likely intended an absolute-value range check. An exploit
developer asks about the edge case `-128`, because negating the most negative
signed byte has representation pitfalls even though this version promoted to
32-bit first.

---
