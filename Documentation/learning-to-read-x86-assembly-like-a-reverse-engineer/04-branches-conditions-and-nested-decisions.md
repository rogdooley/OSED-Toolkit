# Branches, Conditions, and Nested Decisions

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

## Exercises

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

## Challenge problems

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

## Solutions with reasoning

Exercise solution:

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

Challenge solution:

The first comparison limits the accepted domain to `0..3` unsigned. It prevents
large unsigned values from falling into the later chain. Semantically, the
programmer is bounding an opcode or enum before handling selected cases. Values
`0` and `3` are both unhandled in-range values that fall through to the zero
return. An exploit developer asks whether those mappings are intentional default
behavior or accidental gaps in the dispatch logic.

---
