# 3. LEA, MOVSX, MOVZX, TEST, CMP, and SETcc

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

### Signedness cheat sheet

Recognizing signedness from the assembly is one of the most important skills
for exploit analysis, because a signed/unsigned confusion in a length check
is a common vulnerability class.

```text
Instruction    Signedness   Meaning
-----------    ----------   -------
movzx          unsigned     zero-extend: source is unsigned
movsx          signed       sign-extend: source is signed
ja / jb        unsigned     jump if above / below (unsigned compare)
jg / jl        signed       jump if greater / less (signed compare)
jae / jbe      unsigned     above-or-equal / below-or-equal
jge / jle      signed       greater-or-equal / less-or-equal
seta / setb    unsigned     set byte if unsigned above / below
setg / setl    signed       set byte if signed greater / less
imul           signed       signed multiply
mul            unsigned     unsigned multiply
cdq            signed       sign-extend EAX into EDX:EAX for signed division
sar            signed       arithmetic right shift (preserves sign bit)
shr            unsigned     logical right shift (fills with zeros)
```

When the same comparison appears with `ja` in one function and `jg` in
another, the programmer changed the signedness of the check. In exploit
analysis, look for mismatches: a signed comparison on an attacker-supplied
length may allow negative values to bypass a bounds check.

### CDQ, ROL, and ROR

Three instructions that appear frequently in exploit-relevant contexts:

**CDQ** (Convert Doubleword to Quadword): sign-extends EAX into EDX:EAX.
If EAX is positive, EDX becomes 0. If EAX is negative, EDX becomes 0xFFFFFFFF.
The compiler emits CDQ before `idiv` to set up the 64-bit dividend for signed
division. If you see `cdq; idiv ecx`, the division is signed.

**ROL/ROR** (Rotate Left/Right): circular bit rotation. Unlike shifts, bits
that fall off one end wrap to the other. These appear in:

- Hash functions (the ROR-13-ADD hash in shellcode API resolution is a
  key OSED pattern -- see chapter 14).
- Obfuscation and encoding loops.
- Certain multiplication replacements.

```asm
ror eax, 0Dh    ; rotate right 13 bits -- shellcode hash accumulator
rol eax, 8      ; rotate left 8 -- byte swapping or mixing
```

## Exercises

### Exercise 1

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

### Exercise 2

```asm
sub_401260:
    push    ebp
    mov     ebp, esp
    mov     eax, [ebp+8]
    movsx   ecx, word ptr [eax+2]
    test    ecx, ecx
    jl      short negative
    lea     edx, [ecx+ecx]
    jmp     short store
negative:
    neg     ecx
    lea     edx, [ecx+ecx]
store:
    mov     [eax+4], edx
    pop     ebp
    retn
```

Questions:

- What is the source field's width and signedness?
- What does the function compute and store at `[eax+4]`?
- Why does the signed check matter here?

### Exercise 3

```asm
sub_4012A0:
    mov     ecx, [esp+4]
    mov     edx, [esp+8]
    lea     eax, [ecx+edx]
    lea     eax, [eax+eax*2]
    shl     eax, 2
    retn
```

Questions:

- There are no memory accesses after loading the arguments. What do the LEA
  and SHL instructions compute?
- Express the return value as a formula in terms of the two arguments.

## Challenge problems

### Challenge 1

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

### Challenge 2

```asm
sub_4012C0:
    mov     eax, [esp+4]
    movzx   ecx, byte ptr [eax]
    movsx   edx, byte ptr [eax+1]
    cmp     ecx, 80h
    jae     short big
    add     ecx, edx
    test    ecx, ecx
    setg    al
    movzx   eax, al
    retn
big:
    sub     ecx, edx
    cmp     ecx, 100h
    setb    al
    movzx   eax, al
    retn
```

Two bytes from the same structure control different branches. What question is
each path answering? What exploit-relevant signedness issue could arise if an
analyst confused `movzx` and `movsx` for these two bytes?

## Solutions with reasoning

### Exercise 1 solution

The field at offset `+8` is an unsigned byte. It is multiplied by 5 using LEA.
The function returns whether `field * 5 > 100` using an unsigned comparison
(`seta`).

Plausible pseudocode:

```c
int too_large(const unsigned char *p) {
    return p[8] * 5u > 100u;
}
```

### Exercise 2 solution

The source field at `[eax+2]` is a signed 16-bit value (word, sign-extended
by `movsx`). The function computes twice the absolute value of this field and
stores it at `[eax+4]`. On the negative path, `neg ecx` makes it positive
before doubling. The signed check matters because `lea [ecx+ecx]` on a
negative value would produce a negative doubled result -- the programmer wants
a positive magnitude.

Plausible pseudocode:

```c
void compute_magnitude(struct S *s) {
    short val = s->field_2;
    s->field_4 = abs(val) * 2;
}
```

### Exercise 3 solution

No memory is accessed after loading the two integer arguments. `lea eax,
[ecx+edx]` computes `arg0 + arg1`. `lea eax, [eax+eax*2]` computes that
sum times 3. `shl eax, 2` multiplies by 4. The return value is
`(arg0 + arg1) * 12`.

### Challenge 1 solution

The function reads a signed byte at offset `+1`, computes its absolute value, and
returns whether that absolute value is `<= 127`. The interesting semantic clue is
not `neg`; it is the pair `movsx` and `jns`, which shows the original byte was
signed. The programmer likely intended an absolute-value range check. An exploit
developer asks about the edge case `-128`, because negating the most negative
signed byte has representation pitfalls even though this version promoted to
32-bit first.

### Challenge 2 solution

Byte `[eax]` is loaded unsigned (`movzx`), so its range is 0-255. Byte
`[eax+1]` is loaded signed (`movsx`), so its range is -128 to +127.

The unsigned byte is compared against 0x80. If below 0x80 (small path):
the function adds the signed byte and returns whether the sum is positive
(`setg`). If >= 0x80 (big path): the function subtracts the signed byte
and returns whether the result is below 0x100 (`setb`).

If an analyst reversed the signedness -- treating byte 0 as signed and byte 1
as unsigned -- the "small" path's addition would be wrong (a value of 0xFF
sign-extended to -1 instead of zero-extended to 255 changes the sum
entirely), and the security check on the "big" path could be defeated by
negative values wrapping around.

## Key takeaways

- LEA is arithmetic, not a memory read. When the result is not later
  dereferenced, LEA is computing a value (multiplication, addition, or
  address calculation).

- `movsx` vs `movzx` reveals whether the compiler treats a field as signed
  or unsigned. This distinction determines which comparison instructions
  follow (`jg/jl` vs `ja/jb`) and directly affects exploit feasibility.

- `setcc` materializes a boolean from flags. Read it as data flow (producing a
  0 or 1 value), not as control flow (it does not branch).

- CDQ before `idiv` signals signed division. ROL/ROR appear in hash functions
  (especially the ROR-13-ADD pattern in shellcode) and obfuscation.

- Signed/unsigned confusion in length or index checks is a common vulnerability
  class. A signed comparison allows negative values to bypass bounds checks.

## See also

- `x86-osed-assembly-reference/05-eflags-and-conditional-execution.md` --
  detailed flag behavior for every condition code
- `x86-osed-assembly-reference/06-core-instruction-reference.md` -- LEA, MOV,
  MOVSX, MOVZX, CDQ, ROL, ROR instruction semantics
- `x86-osed-assembly-reference/12-arithmetic-used-in-exploit-development.md` --
  arithmetic tricks used in shellcode and exploit payloads
- `osed-reversing-guide/02-instruction-semantics.md` -- reading instructions
  as semantic evidence
- `DRILLS/function_analysis.md` -- practice applying signedness analysis

---
