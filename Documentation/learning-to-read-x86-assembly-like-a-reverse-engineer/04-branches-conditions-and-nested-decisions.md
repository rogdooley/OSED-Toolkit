# 4. Branches, Conditions, and Nested Decisions

## Learning objectives

- Recover if, if/else, guard clauses, and nested branches.
- Determine what condition controls each path.
- Preserve signedness while reconstructing decisions.
- Identify validation gates and trust boundaries.

## Concept discussion

Branches are questions. The jump mnemonic tells you how the flags are
interpreted. `ja` and `jb` are unsigned. `jg` and `jl` are signed. `jz` tests
equality/zero. `jnz` tests inequality/nonzero.

A compiler often emits guard clauses as early jumps to failure. This means the
source may have looked simple even when the assembly appears branch-heavy:

```c
if (!p) return -1;
if (len > max) return -1;
if (!authorized) return -1;
...
return 0;
```

The reverse engineer should read these as successive requirements, not as
unrelated fragments.

## Common compiler patterns

- `test p,p; jz fail`: null guard.
- `cmp len,max; ja fail`: unsigned length guard.
- `cmp status,0; jl fail`: signed error check.
- `cmp type,n; jne next_case`: decision chain.
- Common failure block with `mov eax,-1`: validation helper.

## Fully annotated example

```asm
sub_401300:
    push    ebp
    mov     ebp, esp
    mov     eax, [ebp+8]
    test    eax, eax
    jz      fail
    mov     ecx, [ebp+0Ch]
    cmp     ecx, 100h
    ja      fail
    cmp     byte ptr [eax], 2
    jnz     fail
    xor     eax, eax
    pop     ebp
    retn
fail:
    mov     eax, 0FFFFFFFFh
    pop     ebp
    retn
```

Annotated:

```asm
test eax, eax / jz fail
; Requirement 1: pointer argument must be non-null.

cmp ecx, 100h / ja fail
; Requirement 2: unsigned length must be <= 256.

cmp byte ptr [eax], 2 / jnz fail
; Requirement 3: first byte of pointed-to buffer must equal type 2.
```

The CPU is answering three guard questions. The programmer likely wrote a
validator for a record. The compiler assumes `len` is unsigned or size-like
because it used `ja`.

## Reverse engineering thought process

Rewrite branches into path requirements:

```text
success path requires:
  p != NULL
  len <= 0x100 unsigned
  p[0] == 2
failure path:
  any requirement fails
```

This is more useful than immediately writing C because it exposes which values
become trusted after each check.

## Common mistakes

- Inverting a condition incorrectly when following taken vs fall-through edges.
- Losing unsigned/signed distinction.
- Treating each guard as independent after a prior guard has constrained a value.
- Missing that a dereference after a guard depends on the guard.

### CMOVcc -- conditional moves

MSVC and optimizing compilers sometimes replace short if/else branches with
conditional move instructions:

```asm
cmp     eax, ecx
cmovb   eax, ecx       ; if eax < ecx (unsigned), eax = ecx
```

CMOVcc executes the move only if the condition flags match. It avoids a branch
prediction penalty. The semantic meaning is the same as a branch, but the
control flow is linear -- there is no jump target to follow.

Common CMOVcc patterns:

```text
cmovz  / cmove     Move if zero/equal
cmovnz / cmovne    Move if nonzero/not equal
cmovb  / cmovc     Move if below (unsigned) / carry
cmovae / cmovnc    Move if above-or-equal (unsigned) / no carry
cmovg              Move if greater (signed)
cmovl              Move if less (signed)
```

When you see CMOVcc, reconstruct the if/else by reading the condition and the
two possible values. The instruction that sets flags (CMP or TEST) is always
immediately before or nearby.

## Exercises

### Exercise 1

```asm
sub_401340:
    mov     eax, [esp+4]
    test    eax, eax
    jz      deny
    cmp     dword ptr [eax+0Ch], 0
    jle     deny
    cmp     dword ptr [eax+10h], 400h
    ja      deny
    mov     eax, 1
    retn
deny:
    xor     eax, eax
    retn
```

Questions:

- Which comparisons are signed and unsigned?
- What requirements must hold for success?
- Which fields are probably length/count-like?

### Exercise 2

```asm
sub_4013B0:
    push    ebp
    mov     ebp, esp
    mov     eax, [ebp+8]
    mov     ecx, [ebp+0Ch]
    cmp     eax, ecx
    jae     short use_ecx
    mov     edx, ecx
    sub     edx, eax
    cmp     edx, 10h
    ja      short too_far
    mov     eax, edx
    pop     ebp
    retn
use_ecx:
    mov     eax, ecx
    pop     ebp
    retn
too_far:
    xor     eax, eax
    pop     ebp
    retn
```

Questions:

- How many distinct exit paths are there?
- What does each path return?
- What validation pattern does this implement?

### Exercise 3

```asm
sub_4013D0:
    mov     ecx, [esp+4]
    test    ecx, ecx
    jz      short ret_neg
    mov     eax, [ecx+8]
    test    eax, eax
    jz      short ret_neg
    cmp     dword ptr [eax], 0DEADh
    jnz     short ret_neg
    mov     eax, [eax+4]
    retn
ret_neg:
    mov     eax, 0FFFFFFFFh
    retn
```

Questions:

- How many levels of pointer indirection are validated?
- What is the "magic" check protecting?
- What does the function return on the success path?

## Challenge problems

### Challenge 1

```asm
sub_401380:
    mov     eax, [esp+4]
    cmp     eax, 3
    ja      default
    cmp     eax, 1
    jz      one
    cmp     eax, 2
    jz      two
    xor     eax, eax
    retn
one:
    mov     eax, 10h
    retn
two:
    mov     eax, 20h
    retn
default:
    mov     eax, 0FFFFFFFFh
    retn
```

Explain why the first `cmp eax,3; ja default` matters even though only cases 1
and 2 have special code.

### Challenge 2

```asm
sub_401400:
    push    ebp
    mov     ebp, esp
    mov     eax, [ebp+8]
    mov     ecx, [ebp+0Ch]
    cmp     ecx, eax
    cmovb   eax, ecx
    mov     ecx, [ebp+10h]
    cmp     ecx, eax
    cmovb   eax, ecx
    pop     ebp
    retn
```

What does this function compute? Rewrite as C. Why might the compiler prefer
CMOVcc over branches here?

## Solutions with reasoning

### Exercise 1 solution

Success requires a non-null pointer, a signed positive field at `+0x0C`, and an
unsigned field at `+0x10` no greater than `0x400`. The second field is probably
size-like because of the unsigned comparison.

Plausible pseudocode:

```c
int allowed(const struct X *x) {
    if (!x) return 0;
    if (x->signed_count <= 0) return 0;
    if (x->length > 0x400u) return 0;
    return 1;
}
```

### Exercise 2 solution

Three exit paths:
1. If `arg0 >= arg1` (unsigned): return `arg1`.
2. If `arg1 - arg0 > 0x10`: return 0.
3. Otherwise: return `arg1 - arg0`.

The function computes a bounded unsigned difference. If the first argument is
already at or past the second, it returns the second value (a floor). If the
gap is too large (> 16), it rejects. Otherwise it returns the gap. This looks
like a clamped distance calculation, possibly for a sliding window or offset
within a buffer.

### Exercise 3 solution

Two levels of pointer indirection: first `[esp+4]` is dereferenced to get a
pointer at `[ecx+8]`, then that pointer is dereferenced to read a dword tag
at `[eax]`. The function validates both pointers (null checks) and then
verifies a magic value `0xDEAD` at the base of the second-level object.
On the success path, it returns `[eax+4]` -- a field from the magic-tagged
object.

This is a common pattern for following a pointer chain in a runtime structure
(e.g., object -> subobject -> tagged data) with defensive checks at each level.

### Challenge 1 solution

The first comparison limits the accepted domain to `0..3` unsigned. It prevents
large unsigned values from falling into the later chain. Semantically, the
programmer is bounding an opcode or enum before handling selected cases. Values
`0` and `3` are both unhandled in-range values that fall through to the zero
return. An exploit developer asks whether those mappings are intentional default
behavior or accidental gaps in the dispatch logic.

### Challenge 2 solution

The function computes the minimum of three unsigned values. `cmovb` (conditional
move if below, unsigned) replaces EAX with ECX only if ECX is smaller. After
two comparisons, EAX holds the smallest of the three arguments.

```c
unsigned min3(unsigned a, unsigned b, unsigned c) {
    if (b < a) a = b;
    if (c < a) a = c;
    return a;
}
```

The compiler prefers CMOVcc because the branches are short, unpredictable (the
smallest value could be any of the three), and a branch misprediction penalty
would be larger than the unconditional data dependency of CMOVcc. For small
if/else bodies with no side effects, CMOVcc avoids the branch predictor entirely.

## Key takeaways

- Read branches as path requirements, not as isolated jumps. "Success requires
  p != NULL AND len <= max AND type == 2" is more useful than three separate
  jump annotations.

- Signed vs. unsigned conditions (`jg/jl` vs `ja/jb`) reveal the programmer's
  type assumptions. Mismatches between signed checks and unsigned data are a
  vulnerability class.

- Guard clauses (early jumps to failure) are the most common pattern in
  validation code. Identify the gates, then identify what becomes trusted
  after each gate.

- CMOVcc replaces short branches in optimized code. Read it as a conditional
  assignment: "if condition, dest = source."

- Nested pointer validation (null check -> dereference -> null check ->
  dereference) is common in object-oriented code. Each level adds a trust
  assumption that an exploit developer must verify.

## See also

- `x86-osed-assembly-reference/05-eflags-and-conditional-execution.md` --
  comprehensive coverage of all condition codes
- `x86-osed-assembly-reference/10-branches-and-control-flow.md` -- branch
  patterns, if/else lowering, loop structures
- `osed-reversing-guide/04-branching-and-conditions.md` -- branch analysis
  methodology
- `DRILLS/function_analysis.md` -- practice recovering guard chains

---
